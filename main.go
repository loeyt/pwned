package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/urfave/cli"
)

func main() {
	var progress bool
	var hashString string

	app := cli.NewApp()
	app.Usage = "A tool to search the Pwned Password list efficiently"
	app.UsageText = "pwned check <file>...\n   pwned search --hash <SHA-1 hash of password> <file>..."
	app.Commands = []cli.Command{
		{
			Name:      "check",
			Usage:     "Checks files to be the correct Pwned Password list format",
			UsageText: "pwned check [--progress] <file>...",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:        "progress, p",
					Usage:       "Show progress within the files.",
					Destination: &progress,
				},
			},
			Action: func(c *cli.Context) error {
				if c.NArg() == 0 {
					cli.ShowCommandHelpAndExit(c, "check", 1)
				}
				for _, filename := range c.Args() {
					fmt.Printf("checking file %q: ", filename)
					err := checkFile(filename, progress)
					if err == nil {
						fmt.Printf("OK\n")
					} else {
						fmt.Printf("%v\n", err)
					}
				}
				return nil
			},
		},
		{
			Name:      "search",
			Usage:     "Runs a binary search for a hash in the Pwned Password list",
			UsageText: "pwned search --hash <SHA-1 hash of password> <file>...",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "hash",
					Usage:       "SHA-1 hash to look for (in uppercase hexadecimal notation)",
					Destination: &hashString,
				},
			},
			Action: func(c *cli.Context) error {
				if c.NArg() == 0 {
					cli.ShowCommandHelpAndExit(c, "search", 1)
				}
				if hashString == "" {
					cli.ShowCommandHelpAndExit(c, "search", 1)
				}
				for _, filename := range c.Args() {
					fmt.Printf("searching file %q: ", filename)
					match, err := searchFile(filename, hashString)
					if err != nil {
						fmt.Println("error:", err)
						return err
					}
					if match != -1 {
						fmt.Printf("hash %d matched! (byte offset %d)\n", match+1, match*42)
						return nil
					}
					fmt.Println("no match.")
				}
				return nil
			},
		},
	}
	app.Run(os.Args)
}

func checkFile(filename string, progress bool) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	var buf [42]byte
	n, mod := 0, 1
	if progress {
		fmt.Print("\033[s")
	}
	for {
		n++
		_, err = f.Read(buf[:])
		if err == io.EOF {
			if !progress {
				if n > 1000000 {
					fmt.Printf("%dM ", n/1000000)
				} else if n > 1000 {
					fmt.Printf("%dK ", n/1000)
				} else {
					fmt.Printf("%d ", n)
				}
			}
			return f.Close()
		}
		if err != nil {
			_ = f.Close()
			return err
		}
		for _, c := range buf[:40] {
			switch c {
			case
				'0', '1', '2', '3', '4', '5', '6', '7',
				'8', '9', 'A', 'B', 'C', 'D', 'E', 'F':
			default:
				_ = f.Close()
				return fmt.Errorf("hash %d contained characters other than [0-9A-F]", n)
			}
		}
		if buf[40] != '\r' || buf[41] != '\n' {
			_ = f.Close()
			return fmt.Errorf("hash %d didn't end with CR + LF", n)
		}
		if progress && n%mod == 0 {
			if n/mod == 1000 {
				mod *= 1000
			}
			m := ' '
			switch mod {
			case 1000:
				m = 'K'
			case 1000000:
				m = 'M'
			}
			fmt.Printf("\033[u\033[K%d%c ", n/mod, m)
		}
	}
}

func searchFile(filename string, hashString string) (int, error) {
	f, err := os.Open(filename)
	if err != nil {
		return -1, err
	}
	fi, err := f.Stat()
	if err != nil {
		return -1, err
	}
	if fi.Size()%42 != 0 {
		return -1, fmt.Errorf("file size not a multiple of 42")
	}
	hashBytes := []byte(hashString)
	buf := make([]byte, 42)
	i := sort.Search(int(fi.Size()/42), func(i int) bool {
		if err != nil {
			return false
		}
		_, err = f.Seek(int64(i)*42, 0)
		if err != nil {
			return false
		}
		_, err = f.Read(buf)
		if err != nil {
			return false
		}
		if bytes.Compare(buf[:40], hashBytes) < 0 {
			return false
		}
		return true
	})
	_, err = f.Seek(int64(i)*42, 0)
	if err != nil {
		return -1, err
	}
	_, err = f.Read(buf)
	if err != nil {
		return -1, err
	}
	if bytes.Equal(buf[:40], hashBytes) {
		return i, nil
	}
	return -1, nil
}
