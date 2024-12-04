package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sync/semaphore"
)

// fixme: add short versions to flags once i made the package for it
func main() {
	var blokesize int64
	flag.Int64Var(&blokesize, "blocksize", 4096, "size of the block in bytes to read from each file for hashing")

	var deepthroat bool
	flag.BoolVar(&deepthroat, "deepthroat", false, "do a full file compare to ensure it is not just a partial match")

	var flat bool
	flag.BoolVar(&flat, "flat", false, "do not inspect subfolders recursively")

	var minfilesize int64
	flag.Func("minfilesize", "filter out pointless small files. format is human readable for example 1mb or 2gigabyte", func(s string) error {
		sz, err := parseHumanFileSize(s)
		if err != nil {
			return fmt.Errorf("failed to parse minsize: %w", err)
		}
		minfilesize = sz
		return nil
	})

	var numslaves int64
	flag.Int64Var(&numslaves, "slaves", 128, "amount of parallel file inspectors") // pure dice roll

	flag.Parse()
	// just in case someone wants to be cheeky
	if numslaves < 1 {
		numslaves = 128
	}
	if blokesize < 1 {
		blokesize = 4096
	}

	// figure out the path
	var rootdir string
	if len(flag.Args()) > 0 {
		rootdir = flag.Arg(0)
	} else {
		rootdir = "."
	}
	rootdir, err := filepath.Abs(rootdir)
	if err != nil {
		panic(fmt.Errorf("invalid path: %w", err))
	}
	fi, err := os.Stat(rootdir)
	if err != nil {
		panic(fmt.Errorf("cant access path: %w", err))
	}
	if !fi.IsDir() {
		// you can also drop a file here and it will run the
		// tool against its parent dir. QOL.
		rootdir = filepath.Dir(rootdir)
	}
	rootdir = filepath.Clean(rootdir)

	var files []string
	var hashes []string
	var mu sync.Mutex
	sem := semaphore.NewWeighted(numslaves)
	ctx := context.TODO()
	hashfile := func(path string) {
		sem.Acquire(ctx, 1)
		go func(path string) {
			defer sem.Release(1)

			f, err := os.Open(path)
			if err != nil {
				return
			}

			h := md5.New()
			io.Copy(h, io.LimitReader(f, blokesize))
			hash := hex.EncodeToString(h.Sum(nil))

			mu.Lock()
			files = append(files, path)
			hashes = append(hashes, hash)
			mu.Unlock()

			f.Close()
		}(path)
	}

	amount := 0
	walk := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if flat && info.Mode().IsDir() && path != rootdir {
			return filepath.SkipDir

		}
		// ignores directories, symlinks and maybe other stuff
		// we dont care about. openfile will tell us.
		if !info.Mode().IsRegular() {
			return nil
		}

		if info.Size() >= minfilesize {
			//fmt.Println("file:", path)
			hashfile(path)
		}

		amount++
		return nil
	}
	filepath.Walk /*a lonely road*/ (rootdir, walk)

	sem.Acquire(ctx, numslaves)
	sem.Release(numslaves)
	fmt.Println("Checked files:", amount)

	if deepthroat {
		fmt.Println("Deepthroating", len(files), "files")
		var files2 []string
		var hashes2 []string
		var mu sync.Mutex

		for _, file := range files {
			sem.Acquire(ctx, 1)
			go func(file string) {
				defer sem.Release(1)

				f, err := os.Open(file)
				if err != nil {
					return // dont care
				}

				h := md5.New()
				io.Copy(h, f)
				hash := hex.EncodeToString(h.Sum(nil))

				mu.Lock()
				files2 = append(files2, file)
				hashes2 = append(hashes2, hash)
				mu.Unlock()

				f.Close()
			}(file)
		}

		sem.Acquire(ctx, numslaves)
		sem.Release(numslaves)

		hashes = hashes2
		files = files2
	}

	everything := make(map[string][]string)
	for i := range files {
		load := everything[hashes[i]]
		load = append(load, files[i])
		everything[hashes[i]] = load
	}

	numdupes := 0
	for hash, files := range everything {
		ll := len(files)
		if ll >= 2 {
			numdupes += ll
			fmt.Printf("%s exists %d times\n\t%s\n\n", hash, ll, strings.Join(files, "\n\t"))
		}
	}

	fmt.Println("Dupes found:", numdupes)
}

// adapted from https://github.com/c2h5oh/datasize/blob/aa82cc1e65004e2b59a6e44d26f774ca961b24d8/datasize.go#L116
func parseHumanFileSize(s string) (int64, error) {
	const (
		B  int64 = 1
		KB       = B << 10
		MB       = KB << 10
		GB       = MB << 10
		TB       = GB << 10
		PB       = TB << 10

		maxInt64 int64 = math.MaxInt64
		cutoff   int64 = maxInt64 / 10
	)
	errOverflow := errors.New("overflow error")

	var val int64
	var unit string

	var c byte
	var i int
	t := []byte(s)
	for i < len(t) {
		c = t[i]
		switch {
		case '0' <= c && c <= '9':
			if val > cutoff {
				return 0, errOverflow
			}

			c = c - '0'
			val *= 10

			if val > val+int64(c) {
				// val+v overflows
				return 0, errOverflow
			}
			val += int64(c)
			i++
			continue
		}

		if i == 0 {
			return 0, errors.New("syntax error")
		}
		break
	}

	unit = strings.TrimSpace(string(t[i:]))
	switch unit {
	case "Kb", "Mb", "Gb", "Tb", "Pb", "Eb":
		return 0, errors.New("unit with capital unit prefix and lower case unit (b) - bits, not bytes ")
	}
	unit = strings.ToLower(unit)
	switch unit {
	case "", "b", "byte":
		// do nothing - already in bytes

	case "k", "kb", "kilo", "kilobyte", "kilobytes":
		if val > maxInt64/int64(KB) {
			return 0, errOverflow
		}
		val *= int64(KB)

	case "m", "mb", "mega", "megabyte", "megabytes":
		if val > maxInt64/int64(MB) {
			return 0, errOverflow
		}
		val *= int64(MB)

	case "g", "gb", "giga", "gigabyte", "gigabytes":
		if val > maxInt64/int64(GB) {
			return 0, errOverflow
		}
		val *= int64(GB)

	case "t", "tb", "tera", "terabyte", "terabytes":
		if val > maxInt64/int64(TB) {
			return 0, errOverflow
		}
		val *= int64(TB)

	case "p", "pb", "peta", "petabyte", "petabytes":
		if val > maxInt64/int64(PB) {
			return 0, errOverflow
		}
		val *= int64(PB)

	default:
		return 0, fmt.Errorf("unknown unit specifier: %s", unit)
	}

	if val < 0 {
		panic("i messed up")
	}

	return int64(val), nil
}
