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
    "os/exec" //clear the screen once the password is displayed
	"time"
	"strings"
	//"math/rand"
	"crypto/rand" // crypto rand is more secure.
	"bytes"
    "strconv"
    "crypto/cipher" // for password encryption
    "crypto/aes" // for password encryption too
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
    entryName []byte   // Should be exactly 32 bytes with zero right padding
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

////////////////////////////////////////////////////////////////////////////////
//
// Function     : makePassword
// Description  : Ask for a password twice and not echoed in the terminal
//
// Inputs       : none
// Outputs      : The password padded on 32 bytes []byte{pwd,0x0,0x0...}

func makePassword(requestInput string, maxLength int) []byte{
	password_1 := []byte{}
	password_2 := []byte{}

	for !bytes.Equal(password_1, password_2) || len(password_1) == 0{
		if  len(password_1) == 0 {
			fmt.Print(requestInput)
		} else {
			fmt.Print("\nType the password again please: ")
		}
		bytePassword, err := terminal.ReadPassword(0)
	  if err == nil && len(bytePassword) <= maxLength && len(password_1) == 0{
			password_1 = make([]byte, maxLength, maxLength)
			copy(password_1, bytePassword)
	  } else if err == nil && len(bytePassword) <= maxLength && len(password_1) != 0{
			//pwd_1 already filled
			password_2 = make([]byte, maxLength, maxLength)
			copy(password_2, bytePassword)
		} else if len(bytePassword) > maxLength {
            fmt.Print("\nPassword too long, it must be less than "+ strconv.Itoa(maxLength) +" characters.")
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
// Function     : AES128GCMEncrypt
// Description  : Encrypt password with AES 128 or AES 256 depending on the size of the key
//                Inspired from https://golang.org/src/crypto/cipher/example_test.go
//
// Inputs       : The key, the plaintext and the salt generated
// Outputs      : The ciphertext

func AES128GCMEncrypt(key []byte, plaintext []byte, salt []byte) []byte{
  	// The key argument should be the AES key, either 16 or 32 bytes
  	// to select AES-128 or AES-256.  
    // Never use more than 2^32 random salt with a given key because of the risk of a repeat.
  	block, err := aes.NewCipher(key)
  	if err != nil {
  		panic(err.Error())
  	}
  	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
    /*In CBC mode, you encrypt a block of data by taking the current plaintext block and exclusive-oring that wth the previous ciphertext block (or IV), and then sending the result of that through the block cipher; the output of the block cipher is the ciphertext block.

    GCM mode provides both privacy (encryption) and integrity. To provide encryption, GCM maintains a counter; for each block of data, it sends the current value of the counter through the block cipher. Then, it takes the output of the block cipher, and exclusive or's that with the plaintext to form the ciphertext.*/
  	if err != nil {
  		panic(err.Error())
  	}
    
  	ciphertext := aesgcm.Seal(nil, salt, plaintext, nil)
    if verbose {
        fmt.Printf("\n-- Encrypted password AES-128: %x\n", ciphertext)
    }
    return ciphertext
  }

////////////////////////////////////////////////////////////////////////////////
//
// Function     : AES128GCMDecrypt
// Description  : Decrypt password with AES 128 or AES 256 depending on the size of the key
//                Inspired from https://golang.org/src/crypto/cipher/example_test.go
//
// Inputs       : The key, the ciphertext and the salt generated before
// Outputs      : The plaintext

  func AES128GCMDecrypt(key []byte, ciphertext []byte, salt []byte) []byte{
  	// The key argument should be the AES key, either 16 or 32 bytes
  	// to select AES-128 or AES-256.
    
  	block, err := aes.NewCipher(key)
  	if err != nil {
  		panic(err.Error())
  	}
  	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
  	if err != nil {
  		panic(err.Error())
  	}
  	plaintext, err := aesgcm.Open(nil, salt, ciphertext, nil)
  	if err != nil {
  		panic(err.Error())
  	}
  
    if verbose {
        fmt.Printf("\n-- Decrypted password AES-128: %x\n", plaintext)
    }
    return plaintext
  }

////////////////////////////////////////////////////////////////////////////////
//
// Function     : addPassword
// Description  : Add a entry to the wallet
//
// Inputs       : The wallet
// Outputs      : none, modify the wallet

func (wal443 *wallet) addPassword(){
    generationNumber += 1
    reader := bufio.NewReader(os.Stdin) //Read the input in the terminal
    fmt.Print("\nName the new entry: ")
    
    //Get the entry name
    entryNameString, err := reader.ReadString('\n') //entryName is a string
    for err != nil || len(entryNameString) > 32 {
        fmt.Print("\nAn error occurred, try again (lenght<32 caracters): ")
        entryNameString, err = reader.ReadString('\n') //entryName is a string
    }
    entryName := make([]byte, 32, 32)
    copy(entryName, entryNameString)
    

    //Genarate the random salt
	salt := make([]byte, 16, 16)
	_, err = rand.Read(salt)
    
    //Get the password for the entry
    password := makePassword("\nCreate password for this entry: ", 16)    
    
    //Get the comment section
    fmt.Print("\nAdd a comment for this entry: ")
    commentString, err := reader.ReadString('\n') //comment is a string
    for err != nil || len(commentString) > 128 {
        fmt.Print("\nAn error occurred, try again (lenght<32 caracters): ")
        commentString, err = reader.ReadString('\n') //comment is a string
    }
    comment := make([]byte, 32, 32)
    copy(comment, commentString)
    
    var entryAdded walletEntry
    entryAdded.entryName = entryName
    entryAdded.password = password
	entryAdded.salt = salt
    entryAdded.comment = comment
    
    wal443.passwords = append(wal443.passwords, entryAdded)
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : showList
// Description  : Show the wallet entries list
//
// Inputs       : The wallet
// Outputs      : none 

func (wal443 wallet) showList(){
    fmt.Printf("\n-------- Show List "+string(wal443.filename)+" --------\n")
    for i, entry := range wal443.passwords{
        fmt.Printf("\n["+strconv.Itoa(i)+"] Name: "+string(entry.entryName) +" - Comment: " +string(entry.comment) + "\n")
    }
    if len(wal443.passwords) == 0 {
    fmt.Printf("List empty...")
    }
    fmt.Printf("\n-------- End of the list --------\n")
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : deletePassword
// Description  : Delete an entry from the entries list
//
// Inputs       : The wallet
// Outputs      : none 

func (wal443 *wallet) deletePassword(){
    wal443.showList()
    
    if len(wal443.passwords) == 0{
        fmt.Print("\nAborting, list empty.\n")
        os.Exit(-1)
    }
    
    //Get the id of the entry to delete.
    fmt.Print("\nType the number of the entry you want to delete: ")
    
    reader := bufio.NewReader(os.Stdin) //Read the input in the terminal
    entryDeletedString, errRead := reader.ReadString('\n')
    entryDeletedString = strings.TrimRight(entryDeletedString, "\n")
    entryDeleted, errConv := strconv.Atoi(entryDeletedString)
    for errRead != nil || errConv != nil || len(wal443.passwords)-1 < entryDeleted || entryDeleted < 0{
        fmt.Print("\nPlease type a valid number: ")
        entryDeletedString, errRead = reader.ReadString('\n')
        entryDeletedString = strings.TrimRight(entryDeletedString, "\n")
        entryDeleted, errConv = strconv.Atoi(entryDeletedString)
    }
    
    fmt.Printf("\nAre you sure you want to delete the following entry ?")
    fmt.Printf("\n["+entryDeletedString+"] Name: "+string(wal443.passwords[entryDeleted].entryName) +" - Comment: " +string(wal443.passwords[entryDeleted].comment))
    fmt.Printf("\nType YES: ")
    
    confirmation, err := reader.ReadString('\n') //entryName is a string
    confirmation = strings.TrimRight(confirmation, "\n")
    for strings.Compare(confirmation,"YES") != 0 || err != nil{
        fmt.Printf("Please type \"YES\" :")
        confirmation, err = reader.ReadString('\n') //entryName is a string
        confirmation = strings.TrimRight(confirmation, "\n")
    }
    
    if strings.TrimRight(confirmation, "\n") == "YES"{
        wal443.passwords = append(wal443.passwords[:entryDeleted], wal443.passwords[entryDeleted+1:]...)
        fmt.Printf("\n-------- Entry removed --------\n")
    } else {
        fmt.Printf("\n-------- Abort --------\n")
    }
    
    wal443.showList()
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : showPassword
// Description  : show an entry from the entries list with password in clear
//
// Inputs       : The wallet
// Outputs      : none 

func (wal443 *wallet) showPassword(){
    wal443.showList()
    
    if len(wal443.passwords) == 0{
        fmt.Print("\nAborting, list empty.\n")
        os.Exit(-1)
    }
    
    //Get the id of the entry to show.
    fmt.Print("\nType the number of the entry you want to see: ")
    
    reader := bufio.NewReader(os.Stdin) //Read the input in the terminal
    entryShownString, errRead := reader.ReadString('\n')
    entryShownString = strings.TrimRight(entryShownString, "\n")
    entryShown, errConv := strconv.Atoi(entryShownString)
    for errRead != nil || errConv != nil || len(wal443.passwords)-1 < entryShown || entryShown < 0{
        fmt.Print("\nPlease type a valid number: ")
        entryShownString, errRead = reader.ReadString('\n')
        entryShownString = strings.TrimRight(entryShownString, "\n")
        entryShown, errConv = strconv.Atoi(entryShownString)
    }
    
    
    fmt.Print("\nYou will have 10 seconds to see it: ")
    time.Sleep(3* time.Second)
    fmt.Printf("\n["+entryShownString+"] Name: "+string(wal443.passwords[entryShown].entryName) +" - Comment: " +string(wal443.passwords[entryShown].comment))
    fmt.Printf("\n["+entryShownString+"] Password: "+string(wal443.passwords[entryShown].password)+"\r")
    
    time.Sleep(10* time.Second)
    fmt.Printf("["+entryShownString+"] Password: **********\n")
    
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
    password := makePassword("\nCreate password for wallet: ", 32)

	copy(wal443.masterPassword, password) //wal443.masterPassword contains the pwd now
    fmt.Print("\n-------- Wallet created --------\n")
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
		fmt.Print("\n-- Opening the wallet in ./"+filename+" \n")
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
    fmt.Print("Enter your password: ")
    bytePassword, err := terminal.ReadPassword(0)
    for len(bytePassword) >= 32 || err != nil{
        fmt.Print("\nThe password typed is invalid\n")
        return nil
    }
    
    scanner := bufio.NewScanner(file)
    scanner.Scan()
    firstLine := scanner.Text() + "\n"
    lastLine := scanner.Text() + "\n"
    allLines := scanner.Text() + "\n"
    var allLinesExceptLastOne string = ""
    var allLinesExceptLastOneFirstOne []string
    
    for scanner.Scan(){
        allLinesExceptLastOne = allLines
        allLines += scanner.Text() +"\n"
        lastLine = scanner.Text()
        allLinesExceptLastOneFirstOne = append(allLinesExceptLastOneFirstOne, scanner.Text())
    }
    
    allLinesExceptLastOneFirstOne = allLinesExceptLastOneFirstOne[:len(allLinesExceptLastOneFirstOne)-1]
    
    //Compute HMAC of the file with the password typed
    passwordPadded := make([]byte, 32, 32)
    copy(passwordPadded, bytePassword)
    hashedPassword := sha1.Sum(passwordPadded)
    toHMAC := bytes.Join([][]byte{hashedPassword[:16], []byte(allLinesExceptLastOne)},[]byte(""))
    HMAC := hmac.New(sha1.New, toHMAC).Sum(nil)
    
    //Decode HMAC stored in file
    HMACFromFile64 := strings.TrimRight(lastLine, "\n") // remove the \n at the end
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
    for _, lineEntry := range allLinesExceptLastOneFirstOne{
        lineSplitted := strings.Split(lineEntry, "||")
        var entry walletEntry
        entry.entryName = []byte(lineSplitted[0])
        entry.salt, _ = base64.StdEncoding.DecodeString(lineSplitted[1])
        
        cipher, _ := base64.StdEncoding.DecodeString(lineSplitted[2])
        entry.password = AES128GCMDecrypt(hashedPassword[:16], cipher, entry.salt)
        entry.comment = []byte(lineSplitted[3])
        
        wal443.passwords = append(wal443.passwords, entry)
    }
    
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
		fmt.Print("\n-- Saving the wallet in ./"+wal443.filename+" \n")
	}

    file, err := os.Create(wal443.filename)
    if err != nil {
        fmt.Print("\nAn error occured while trying to save the file.\n", err)
        return false
    }
    defer file.Close()
    //Compute new first line
    var firstLine string = time.Now().Format("Mon Jan 2 15:04:05 2006")+"||"+strconv.Itoa(generationNumber)+"||\n"
    if _, err := file.WriteString(firstLine); err != nil { //Replace first line
        fmt.Print("\nAn error occured while trying to write in the file.\n", err)
        return false
    }

    hashedPassword := sha1.Sum(wal443.masterPassword)
    AESKey := hashedPassword[:16] // 16 bytes = 128-bit
    allLinesExceptLastOne := firstLine
        
    for _, walletEntry := range wal443.passwords{
        //Generate the hash with the seed and wk...
        salt64 := base64.StdEncoding.EncodeToString(walletEntry.salt)
        cyphertext := AES128GCMEncrypt(AESKey, walletEntry.password, walletEntry.salt)
        cyphertext64 := base64.StdEncoding.EncodeToString(cyphertext) 

        line := strings.Split(string(walletEntry.entryName),"\n")[0] + "||" + salt64 + "||" + cyphertext64 + "||" + strings.Split(string(walletEntry.comment),"\n")[0] + "\n"
        allLinesExceptLastOne += line
        if _, err := file.WriteString(line); err != nil { //Replace line
            fmt.Print("\nAn error occured while trying to write in the file.\n", err)
            return false
        }
    }

    //Add HMAC
    toHMAC := bytes.Join([][]byte{hashedPassword[:16], []byte(allLinesExceptLastOne)},[]byte(""))
    HMAC := hmac.New(sha1.New, toHMAC).Sum(nil)
    HMAC64 := base64.StdEncoding.EncodeToString([]byte(HMAC))

    if _, err := file.WriteString(HMAC64+"\n"); err != nil {
        fmt.Print("\nAn error occured while trying to write in the file.\n", err)
        return false
        
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

func (wal443 *wallet) processWalletCommand(command string) bool {

	// Process the command
	switch command {
	case "add":
		wal443.addPassword()
	case "del":
        wal443.deletePassword()
	case "show":
        wal443.showPassword()

	case "chpw":
		// DO SOMETHING HERE

	case "reset":
		// DO SOMETHING HERE

	case "list":
        wal443.showList()

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
	//rand.Seed(time.Now().UTC().UnixNano()) No need to seed with crypto/rand
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
    
    //clear the screen
    c := exec.Command("clear")
    c.Stdout = os.Stdout
    c.Run()
    
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

