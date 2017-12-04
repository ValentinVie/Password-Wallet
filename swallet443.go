////////////////////////////////////////////////////////////////////////////////
//
//  File           : swallet443.go
//  Description    : This is the implementaiton file for the swallet password
//                   wallet program program.  See assignment details.
//
//  Collaborators  : Valentin Vie
//  Last Modified  : Valentin Vie
//

// Package statement
package main

// Imports
import (
	"fmt"
	"os"
	"time"
	"strings"
	"math/rand"
	"bytes"
    "strconv"
	"crypto/sha1"//for sha1 hash
	"crypto/hmac" //for hmac
	"encoding/base64"//To encode in base64
	"bufio"
	"github.com/pborman/getopt"
	"golang.org/x/crypto/ssh/terminal" // the only package I found to type without echo
)

// Type definition  ** YOU WILL NEED TO ADD TO THESE **

// A single password
type walletEntry struct {
	password []byte    // Should be exactly 32 bytes with zero right padding
	salt []byte        // Should be exactly 16 bytes
	comment []byte     // Should be exactly 128 bytes with zero right padding
}

// The wallet as a whole
type wallet struct {
	filename string
	masterPassword []byte   // Should be exactly 32 bytes with zero right padding
	passwords []walletEntry
}

// Global data
var usageText string = `USAGE: swallet443 [-h] [-v] <wallet-file> [create|add|del|show|chpw|reset|list]

where:
    -h - help mode (display this message)
    -v - enable verbose output

    <wallet-file> - wallet file to manage
    [create|add|del|show|chpw] - is a command to execute, where

     create - create a new wallet file
     add - adds a password to the wallet
     del - deletes a password from the wallet
     show - show a password in the wallet
     chpw - changes the password for an entry in the wallet
     reset - changes the password for the wallet
     list - list the entries in the wallet (without passwords)`

var verbose bool = true

// You may want to create more global variables
var generationNumber int = 1
var allLinesExceptLastOneAndFirstOne string = ""

////////////////////////////////////////////////////////////////////////////////
//
// Function     : makePassword
// Description  : Ask for a password twice and not echoed in the terminal
//
// Inputs       : none
// Outputs      : The password padded on 32 bytes []byte{pwd,0x0,0x0...}

func makePassword() []byte{
	password_1 := []byte{}
	password_2 := []byte{}

	for !bytes.Equal(password_1, password_2) || len(password_1) == 0{
		if  len(password_1) == 0 {
			fmt.Print("\nCreate password for wallet: ")
		} else {
			fmt.Print("\nType the password again please: ")
		}
		bytePassword, err := terminal.ReadPassword(0)
	  if err == nil && len(bytePassword) <= 32 && len(password_1) == 0{
			password_1 = make([]byte, 32, 32)
			copy(password_1, bytePassword)
	  } else if err == nil && len(bytePassword) <= 32 && len(password_1) != 0{
			//pwd_1 already filled
			password_2 = make([]byte, 32, 32)
			copy(password_2, bytePassword)
		} else if len(bytePassword) > 32 {
			fmt.Print("\nPassword too long, it must be less than 32 characters.")
		} else {
			fmt.Print("\nSomething went wrong, please try again.")
			password_1 = []byte{}
			password_2 = []byte{}
		}

		if len(password_1) != 0 && len(password_2) != 0 && !bytes.Equal(password_1, password_2){
			fmt.Print("\nPasswords do not match, try again.\n")
			password_1 = []byte{}
			password_2 = []byte{}
		}
	}
    return password_1
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : addPassword
// Description  : Add a entry to the wallet
//
// Inputs       : The wallet
// Outputs      : none, modify the file internaly

func (wal443 wallet) addPassword(){
    generationNumber += 1
}


////////////////////////////////////////////////////////////////////////////////
//
// Function     : walletUsage
// Description  : This function prints out the wallet help
//
// Inputs       : none
// Outputs      : none

func walletUsage() {
	fmt.Fprintf(os.Stderr, "%s\n\n", usageText)
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : createWallet
// Description  : This function creates a wallet if it does not exist
//
// Inputs       : filename - the name of the wallet file
// Outputs      : the wallet if created, nil otherwise

func createWallet(filename string) *wallet {

	// Setup the wallet
	var wal443 wallet
	wal443.filename = filename
	wal443.masterPassword = make([]byte, 32, 32) // You need to take it from here
	
    // Requesting the password twice from the user
    password := makePassword()

	copy(wal443.masterPassword, password) //wal443.masterPassword contains the pwd now
	if verbose{
		fmt.Print("\n-- Wallet created\n")
	}
	// Return the wallet
	return &wal443
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : loadWallet
// Description  : This function loads an existing wallet
//
// Inputs       : filename - the name of the wallet file
// Outputs      : the wallet if created, nil otherwise

func loadWallet(filename string) *wallet {
	if verbose{
		fmt.Print("-- Opening the wallet in ./"+filename+" \n")
	}
    // Setup the wallet
	var wal443 wallet
	wal443.filename = filename
    
    //load file
    file, err := os.Open(filename)
    if err != nil {
        fmt.Print("\nAn error occured while trying to open the file.\n")
        return nil
    } 
    defer file.Close()
    
    //ask password
    fmt.Print("\nEnter your password: ")
    bytePassword, err := terminal.ReadPassword(0)
    for len(bytePassword) >= 32 || err != nil{
        fmt.Print("\nWrong password. Aborting.\n")
        return nil
    }
    
    scanner := bufio.NewScanner(file)
    scanner.Scan()
    firstLine := scanner.Text()
    file.Seek(0, 2) // pointer to the end
    scanner.Scan()
    lastLine := scanner.Text()
    
    file.Seek(0, 0) // pointer to the begining again
    var allLines string = ""
    var allLinesExceptLastOne string = ""
    for scanner.Scan(){
        allLinesExceptLastOneAndFirstOne = allLinesExceptLastOne
        allLinesExceptLastOne = allLines
        allLines += scanner.Text() +"\n"
    }
    
    //Compute HMAC of the file with the password typed
    passwordPadded := make([]byte, 32, 32)
    copy(passwordPadded, bytePassword)
    hashedPassword := sha1.Sum(passwordPadded)
    toHMAC := bytes.Join([][]byte{hashedPassword[:16], []byte(allLinesExceptLastOne)},[]byte(""))
    HMAC := hmac.New(sha1.New, toHMAC).Sum(nil)
    
    //Decode HMAC stored in file
    HMACFromFile64 := strings.Split(lastLine,"\n")[0] // remove the \n at the end
    HMACFromFile, _ := base64.StdEncoding.DecodeString(HMACFromFile64)
    
    //Check equality
    if hmac.Equal(HMACFromFile, HMAC){ //Does not leak timing info
        fmt.Print("\nPassword accepted.\n")
        wal443.masterPassword = passwordPadded
    } else {
        fmt.Print("\nWrong password. Aborting.\n")
        return nil
    }
    
    //Set the generationNumber
    firstLineSplitted := strings.Split(firstLine,"||")
    generationNumberTemp, err := strconv.Atoi(firstLineSplitted[1])
    if err == nil{
        generationNumber = generationNumberTemp
    } else {
        fmt.Print("\nFile corrupted. Aborting\n")
        os.Exit(-1)
    }
    
    //Create the wallet object, loading all infos
    //TODO
	// Return the wallet
	return &wal443
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : saveWallet
// Description  : This function save a wallet to the file specified
//
// Inputs       : walletFile - the name of the wallet file
// Outputs      : true if successful test, false if failure

func (wal443 wallet) saveWallet() bool {
	if verbose{
		fmt.Print("-- Saving the wallet in ./"+wal443.filename+" \n")
	}
	if generationNumber == 1{ //Creation of the file
		// open input file
		file, err := os.Create(wal443.filename)
		if err != nil {
			fmt.Print("\nAn error occured while trying to create the file.\n", err)
			return false
		}
		defer file.Close()
		//Add first line
		var firstLine string = time.Now().Format("Mon Jan 2 15:04:05 2006")+"||1||\n"
		if _, err := file.Write([]byte(firstLine)); err != nil {
			fmt.Print("\nAn error occured while trying to write in the file.\n", err)
			return false
		}

		//Add HMAC
		hashedPassword := sha1.Sum(wal443.masterPassword)
		toHMAC := bytes.Join([][]byte{hashedPassword[:16], []byte(firstLine)},[]byte(""))
		HMAC := hmac.New(sha1.New, toHMAC).Sum(nil)
		HMAC64 := base64.StdEncoding.EncodeToString([]byte(HMAC))

		if _, err := file.Write([]byte(HMAC64+"\n")); err != nil {
			fmt.Print("\nAn error occured while trying to write in the file.\n", err)
			return false
		}
    } else { //Save but change the first line and the HMAC
        file, err := os.OpenFile(wal443.filename, os.O_RDWR|os.O_TRUNC, 0644) // Read && Write
		if err != nil {
			fmt.Print("\nAn error occured while trying to open the file.\n", err)
			return false
		}
		defer file.Close()
		//Compute new first line
        var firstLine string = time.Now().Format("Mon Jan 2 15:04:05 2006")+"||"+strconv.Itoa(generationNumber)+"||\n"
		if _, err := file.Write([]byte(firstLine)); err != nil { //Replace first line
			fmt.Print("\nAn error occured while trying to write in the file.\n", err)
			return false
		}
        allLinesExceptLastOneNEW := firstLine + allLinesExceptLastOneAndFirstOne
        
		//Add HMAC
		hashedPassword := sha1.Sum(wal443.masterPassword)
		toHMAC := bytes.Join([][]byte{hashedPassword[:16], []byte(allLinesExceptLastOneNEW)},[]byte(""))
		HMAC := hmac.New(sha1.New, toHMAC).Sum(nil)
		HMAC64 := base64.StdEncoding.EncodeToString([]byte(HMAC))
        
        file.Seek(0,2) //Write at the end, replace the last line
		if _, err := file.Write([]byte(HMAC64+"\n")); err != nil {
			fmt.Print("\nAn error occured while trying to write in the file.\n", err)
			return false
		}
    }
	// Return successfully
	return true
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : processWalletCommand
// Description  : This is the main processing function for the wallet
//
// Inputs       : walletFile - the name of the wallet file
//                command - the command to execute
// Outputs      : true if successful test, false if failure

func (wal443 wallet) processWalletCommand(command string) bool {

	// Process the command
	switch command {
	case "add":
		wal443.addPassword()
	case "del":
		// DO SOMETHING HERE

	case "show":
		// DO SOMETHING HERE

	case "chpw":
		// DO SOMETHING HERE

	case "reset":
		// DO SOMETHING HERE

	case "list":
		// DO SOMETHING HERE

	default:
		// Handle error, return failure
		fmt.Fprintf(os.Stderr, "Bad/unknown command for wallet [%s], aborting.\n", command)
		return false
	}

	// Return sucessfull
	return true
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : main
// Description  : The main function for the password generator program
//
// Inputs       : none
// Outputs      : 0 if successful test, -1 if failure

func main() {

	// Setup options for the program content
	getopt.SetUsage(walletUsage)
	rand.Seed(time.Now().UTC().UnixNano())
	helpflag := getopt.Bool('h', "", "help (this menu)")
	verboseflag := getopt.Bool('v', "", "enable verbose output")

	// Now parse the command line arguments
	err := getopt.Getopt(nil)
	if err != nil {
		// Handle error
		fmt.Fprintln(os.Stderr, err)
		getopt.Usage()
		os.Exit(-1)
	}

	// Process the flags
	fmt.Printf("help flag [%t]\n", *helpflag)
	fmt.Printf("verbose flag [%t]\n", *verboseflag)
	verbose = *verboseflag
	if *helpflag == true {
		getopt.Usage()
		os.Exit(-1)
	}

	// Check the arguments to make sure we have enough, process if OK
	if getopt.NArgs() < 2 {
		fmt.Printf("Not enough arguments for wallet operation.\n")
		getopt.Usage()
		os.Exit(-1)
	}
	fmt.Printf("wallet file [%t]\n", getopt.Arg(0))
	filename := getopt.Arg(0)
	fmt.Printf("command [%t]\n", getopt.Arg(1))
	command := strings.ToLower(getopt.Arg(1))

	// Now check if we are creating a wallet
	if command == "create" {

		// Create and save the wallet as needed
		wal443 := createWallet(filename)
		if wal443 != nil {
			wal443.saveWallet()
		}

	} else {

		// Load the wallet, then process the command
		wal443 := loadWallet(filename)
		if wal443 != nil && wal443.processWalletCommand(command) {
			wal443.saveWallet()
		}

	}

	// Return (no return code)
	return
}

