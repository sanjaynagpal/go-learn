package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

func main() {
	myString := ""
	arguments := os.Args
	if len(arguments) == 1 {
		myString = "Please provide some arguments!!"
	} else {
		myString = arguments[1]
	}
	io.WriteString(os.Stdout, "This is standard output\n")
	io.WriteString(os.Stderr, myString)
	io.WriteString(os.Stderr, "\n")

	// scan stdin
	ScanStdin()

}

func ScanStdin() {
	f := os.Stdin
	defer f.Close()

	var inputValue string
	scanner := bufio.NewScanner(f)

	// scan input and print
	for scanner.Scan() {
		inputValue = scanner.Text()
		fmt.Println(">", inputValue)
		if inputValue == "quit" {
			break
		}
	}

}
