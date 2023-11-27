package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"
	"strconv"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string
	"encoding/hex"

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username         []byte // hashed
	Uuid             uuid.UUID
	Password         []byte            // hashed
	SignKey          userlib.DSSignKey // for Invitation, SharedSpace (as owner), User
	DecKey           userlib.PKEDecKey // for File sym key decryption
	FileKeys         map[string][]byte // for self owned File SymEnc, encrypted by user's EncKey
	HMACkey          []byte            // source key for File
	FileMacs         map[string][]byte
	SharedSpaceUUIDs map[string]uuid.UUID // string being filename in userspace <-- keeps account of files being shared with. To find info when overwriting a File that user doesn't own.
	//SharingSpaceUUIDs map[string]uuid.UUID <- should be in File
	//SharedSpaceOwners map[string][]byte    // key is filename. owner name is hashed

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

/*
	This struct is used for setting datastore and contains the struct we want to store and its HMAC/signature.

Also need to be JSON.Marshaled to put into database.
*/
type Packet struct {
	Marshaled_struct []byte //marshaled and encrypted
	Authentication   []byte
}

type File struct {
	Filename   []byte // hashed
	Uuid       uuid.UUID
	SignKey    userlib.DSSignKey    // for Contents and Count
	HMACkey    []byte               // unused?
	ContentKey []byte               // the encrypted sym (source) key for Contents and Count
	HeadUUID   uuid.UUID            // first Content uuid
	SharedWith map[string]uuid.UUID // unhashed usernames, uuid of sharedSpace <-- keeps account of recipientUsers
}

/* This struct is for storing the actual content of a File */
type Content struct {
	Text []byte // can't be hashed
	//Next_uuid uuid.UUID // uuid.nil if the end
	//Next_mac  []byte    // nil if the end
}

/* This struct is for counting the number of appends for one File*/
type Count struct {
	Count int
}

type Invitation struct {
	//Symkey []byte            // encrypted source sym key for Contents and Count
	//SK     userlib.DSSignKey // for all Contents and Count
	//Head   uuid.UUID         // for first Content
	SSUUID uuid.UUID // so the recipient can find the sharedSpace and store it in its User struct
	//FileSymkey []byte
	//HMACkey []byte
	//Uuid          uuid.UUID // for the file

}

type SharedSpace struct {
	ContentSymkey    []byte               // encrypted source sym key for Contents and Count
	SignKey          userlib.DSSignKey    // for all Contents and Count
	HeadUUID         uuid.UUID            // for first Content
	SharedSpaceUUIDs map[string]uuid.UUID // shared by the recipient of this share <- if the recipient shared to anyone else (key: recipient users unhashed)
	//HMACkey          []byte               // unused?
}

//func GetStructJSON(packetJSON []byte) (structJSON []byte, err error) {
// helper function to unwrap the packet?
// authentication?
//}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	if len(username) == 0 {
		err = errors.New("empty username")
		return nil, err
	}

	hashedUsername := userlib.Hash([]byte(username))
	hashedUUID, err := uuid.FromBytes(hashedUsername[:16])
	if err != nil {
		return nil, err
	}
	// check if uuid exists
	_, exist := userlib.DatastoreGet(hashedUUID)
	if exist {
		err = errors.New("username already exist")
		return nil, err
	}
	hashedPassword := userlib.Argon2Key([]byte(password), hashedUUID[:], 16)

	// generate public key pair, signature key pair, HMAC key
	var verifyKey userlib.DSVerifyKey
	var sign_key userlib.DSSignKey
	var encKey userlib.PKEEncKey
	sign_key, verifyKey, err = userlib.DSKeyGen()
	userdata.SignKey = sign_key
	encKey, userdata.DecKey, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(hex.EncodeToString(hashedUsername)+"DSVerifyKey", verifyKey)
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(hex.EncodeToString(hashedUsername)+"PKEEncKey", encKey)
	if err != nil {
		return nil, err
	}
	userdata.HMACkey = userlib.RandomBytes(16)

	// setting fields of User
	userdata.Uuid = hashedUUID
	userdata.Username = hashedUsername
	userdata.Password = hashedPassword
	userdata.FileKeys = make(map[string][]byte)
	userdata.SharedSpaceUUIDs = make(map[string]uuid.UUID)
	//userdata.SharedSpaceOwners = make(map[string][]byte)
	userdata.FileMacs = make(map[string][]byte)

	// encrypt, sign, store User into datastore
	userdataJSON, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	iv := userlib.RandomBytes(16)
	encrypted := userlib.SymEnc(hashedUUID[:][:16], iv, userdataJSON)

	signature, err := userlib.DSSign(sign_key, encrypted)
	if err != nil {
		return nil, err
	}
	var pac Packet
	pac.Authentication = signature
	pac.Marshaled_struct = encrypted
	pacJSON, err := json.Marshal(pac)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(hashedUUID, pacJSON)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	var pac Packet

	hashedUsername := userlib.Hash([]byte(username))
	hashedUUID, err := uuid.FromBytes(hashedUsername[:16])
	if err != nil {
		return nil, err
	}
	pacJSON, exist := userlib.DatastoreGet(hashedUUID)
	if !exist {
		err = errors.New("username doesn't exist")
		return nil, err
	}
	err = json.Unmarshal(pacJSON, &pac)
	if err != nil {
		return nil, err
	}
	// check if the encrypted & JSON.marshaled User struct has been tempered with
	verify_key, ok := userlib.KeystoreGet(hex.EncodeToString(hashedUsername) + "DSVerifyKey")
	if !ok {
		err = errors.New(fmt.Sprintf("DSVerifyKey for %s doesn't exist", username))
		return nil, err
	}
	err = userlib.DSVerify(verify_key, pac.Marshaled_struct, pac.Authentication)
	if err != nil {
		//err = errors.New("signature for User Packet is not valid")
		return nil, err
	}
	// decrypt the marshaled User struct
	encrypted := pac.Marshaled_struct
	if len(encrypted) < 16 {
		err = errors.New("ciphertext less than 16 bytes")
		return nil, err
	}
	userJSON := userlib.SymDec(hashedUUID[:][:16], encrypted)
	// unmarshal, now we have the actual user struct
	err = json.Unmarshal(userJSON, &userdata)
	if err != nil {
		return nil, err
	}
	// check username
	name_equal := userlib.HMACEqual(hashedUsername, userdata.Username)
	if !name_equal {
		err = errors.New("something wrong with unmarshaled user struct")
		return nil, err
	}
	// check password
	hashedPassword := userlib.Argon2Key([]byte(password), hashedUUID[:], 16)
	equal := userlib.HMACEqual(userdata.Password, hashedPassword)
	if !equal {
		err = errors.New("incorrect password")
		return nil, err
	}

	userdataptr = &userdata
	return userdataptr, nil
}

func userptr_helper(uuid uuid.UUID, hashed_name []byte) (userdataptr *User, err error) {
	var userdata User
	var pac Packet

	pacJSON, exist := userlib.DatastoreGet(uuid)
	if !exist {
		err = errors.New("username doesn't exist")
		return nil, err
	}
	err = json.Unmarshal(pacJSON, &pac)
	if err != nil {
		return nil, err
	}
	// check if the encrypted & JSON.marshaled User struct has been tempered with
	verify_key, ok := userlib.KeystoreGet(hex.EncodeToString(hashed_name) + "DSVerifyKey")
	if !ok {
		err = errors.New(fmt.Sprintf("DSVerifyKey for %s doesn't exist", hashed_name))
		return nil, err
	}
	err = userlib.DSVerify(verify_key, pac.Marshaled_struct, pac.Authentication)
	if err != nil {
		//err = errors.New("signature for User Packet is not valid")
		return nil, err
	}
	// decrypt the marshaled User struct
	encrypted := pac.Marshaled_struct
	if len(encrypted) < 16 {
		err = errors.New("ciphertext less than 16 bytes")
		return nil, err
	}
	userJSON := userlib.SymDec(uuid[:][:16], encrypted)
	// unmarshal, now we have the actual user struct
	err = json.Unmarshal(userJSON, &userdata)
	if err != nil {
		return nil, err
	}
	// check username
	name_equal := userlib.HMACEqual(hashed_name, userdata.Username)
	if !name_equal {
		err = errors.New("something wrong with unmarshaled user struct")
		return nil, err
	}

	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	userdata, err = userptr_helper(userdata.Uuid, userdata.Username)
	if err != nil {
		return err
	}
	username_string := hex.EncodeToString(userdata.Username)
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + "+" + username_string))[:16])
	if err != nil {
		return err
	}
	// get the public key of user for future use
	publicKey, exists := userlib.KeystoreGet(username_string + "PKEEncKey")
	if !exists {
		err = errors.New(fmt.Sprintf("public key for %s doesn't exist", username_string))
		return err
	}
	// see if the filename already exist in userspace
	oldfile_pacJSON, exist := userlib.DatastoreGet(storageKey)
	if !exist {
		// create a new file
		var newfile File
		var firstContent Content
		// create the Head Content
		firstContent.Text = content
		//firstContent.Next_mac = nil
		//firstContent.Next_uuid = uuid.Nil
		// generate the uuid of the Content
		uuid_firstContent, err := uuid.FromBytes(userlib.RandomBytes(16))
		if err != nil {
			return err
		}
		newfile.HeadUUID = uuid_firstContent
		hashedFilename := userlib.Hash([]byte(filename))
		newfile.Filename = hashedFilename
		newfile.Uuid = storageKey
		// generate sign key for first content (to be shared), store verify key with firstContent's uuid
		sk, vk, err := userlib.DSKeyGen()
		if err != nil {
			return err
		}
		err = userlib.KeystoreSet(uuid_firstContent.String()+"DSVerifyKey", vk)
		if err != nil {
			return err
		}
		newfile.SignKey = sk
		// generate HMAC source key for Contents authentication
		newfile.HMACkey = userlib.RandomBytes(16)
		// generate sym source key for Contents encryption, encrypt with own public enc key then store
		symkey := userlib.RandomBytes(16)
		// (public key fetched before the if case)
		encrypted_symkey, err := userlib.PKEEnc(publicKey, symkey)
		if err != nil {
			return err
		}
		newfile.ContentKey = encrypted_symkey
		// sharedWith is empty for now
		//var strArray []string
		newfile.SharedWith = make(map[string]uuid.UUID)
		// create a Count
		var count Count
		count.Count = 0
		// store Count
		countJSON, err := json.Marshal(count)
		if err != nil {
			return err
		}
		countUUID, err := uuid.FromBytes(userlib.Hash([]byte(uuid_firstContent.String() + "count"))[:16])
		if err != nil {
			return err
		}
		count_key, err := userlib.HashKDF(symkey, countUUID[:])
		if err != nil {
			return err
		}
		count_key = count_key[:16]
		countJSON_encrypted := userlib.SymEnc(count_key, userlib.RandomBytes(16), countJSON)
		var count_pac Packet
		count_pac.Marshaled_struct = countJSON_encrypted
		count_sig, err := userlib.DSSign(sk, countJSON_encrypted)
		if err != nil {
			return err
		}
		count_pac.Authentication = count_sig
		count_pacJSON, err := json.Marshal(count_pac)
		userlib.DatastoreSet(countUUID, count_pacJSON)
		// store head Content
		firstContentJSON, err := json.Marshal(firstContent)
		firstContent_symkey, err := userlib.HashKDF(symkey, uuid_firstContent[:])
		if err != nil {
			return err
		}
		firstContent_symkey = firstContent_symkey[:16]
		firstContentJSON_encrypted := userlib.SymEnc(firstContent_symkey, userlib.RandomBytes(16), firstContentJSON)
		var fC_pac Packet
		fC_pac.Marshaled_struct = firstContentJSON_encrypted
		fC_sig, err := userlib.DSSign(sk, firstContentJSON_encrypted)
		if err != nil {
			return err
		}
		fC_pac.Authentication = fC_sig
		fC_pacJSON, err := json.Marshal(fC_pac)
		userlib.DatastoreSet(uuid_firstContent, fC_pacJSON)
		// store File:
		// generate a sym key for File, encrypt and store it in userdata
		symkey_file := userlib.RandomBytes(16)
		symkey_file_encrypt, err := userlib.PKEEnc(publicKey, symkey_file)
		if err != nil {
			return err
		}
		userdata.FileKeys[filename] = symkey_file_encrypt
		// json the File
		fileJSON, err := json.Marshal(newfile)
		if err != nil {
			return err
		}
		fileJSON_encrypted := userlib.SymEnc(symkey_file, userlib.RandomBytes(16), fileJSON)
		var file_pac Packet
		file_pac.Marshaled_struct = fileJSON_encrypted
		// generate HMAC for File, put in pac, store in userdata
		file_HMACkey, err := userlib.HashKDF(userdata.HMACkey, storageKey[:])
		if err != nil {
			return err
		}
		file_HMACkey = file_HMACkey[:16]
		file_MAC, err := userlib.HMACEval(file_HMACkey, fileJSON_encrypted)
		file_pac.Authentication = file_MAC
		userdata.FileMacs[filename] = file_MAC
		file_pacJSON, err := json.Marshal(file_pac)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(storageKey, file_pacJSON)

		// store User (because fileKey and fileMac)
		user_uuid := userdata.Uuid
		userdataJSON, err := json.Marshal(userdata)
		if err != nil {
			return err
		}
		iv := userlib.RandomBytes(16)
		encrypted := userlib.SymEnc(user_uuid[:][:16], iv, userdataJSON)
		signature, err := userlib.DSSign(userdata.SignKey, encrypted)
		if err != nil {
			return err
		}
		var pac Packet
		pac.Authentication = signature
		pac.Marshaled_struct = encrypted
		pacJSON, err := json.Marshal(pac)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(user_uuid, pacJSON)

	} else {
		// overwrite old file
		// fetch the old file
		var oldfile_pac Packet
		var oldfile File
		//var newfile File

		err = json.Unmarshal(oldfile_pacJSON, &oldfile_pac)
		if err != nil {
			return err
		}
		// check authentication, HMAC
		MAC_in_user, exists := userdata.FileMacs[filename]
		if !exists {
			err = errors.New("user doesn't have the HMAC for File")
			return err
		}
		file_HMACkey, err := userlib.HashKDF(userdata.HMACkey, storageKey[:])
		if err != nil {
			return err
		}
		file_HMACkey = file_HMACkey[:16]
		MAC_in_pac, err := userlib.HMACEval(file_HMACkey, oldfile_pac.Marshaled_struct)
		if err != nil {
			return err
		}
		equal := userlib.HMACEqual(MAC_in_pac, MAC_in_user)
		if !equal {
			err = errors.New("HMAC doesn't match.")
			return err
		}
		// symmetric decrypt with FileKey from User
		if len(oldfile_pac.Marshaled_struct) < 16 {
			err = errors.New("ciphertext less than 16 bytes")
			return err
		}
		symkey_encrypted, exists := userdata.FileKeys[filename]
		if !exists {
			err = errors.New("user doesn't have the sym key for File")
			return err
		}
		symkey, err := userlib.PKEDec(userdata.DecKey, symkey_encrypted)
		if err != nil {
			return err
		}
		oldfileJSON := userlib.SymDec(symkey, oldfile_pac.Marshaled_struct)
		// unmarshal, now we have the actual File
		err = json.Unmarshal(oldfileJSON, &oldfile)
		if err != nil {
			return err
		}
		var headUUID uuid.UUID
		var symkey_source []byte
		var sk userlib.DSSignKey
		// check if oldfile have HeadUUID. if not, look at SharedSpace
		if oldfile.ContentKey == nil {
			ss_uuid, exist := userdata.SharedSpaceUUIDs[filename]
			// note that if neither have the key, the access is probably revoked. return error
			if !exist {
				err = errors.New(fmt.Sprintf("can't find ss uuid for %s, access probably revoked", filename))
				return err
			}
			ss_pacJSON, ok := userlib.DatastoreGet(ss_uuid)
			if !ok {
				err = errors.New("can't find data under ss_uuid in datastore")
				return err
			}
			var ss_pac Packet
			err = json.Unmarshal(ss_pacJSON, &ss_pac)
			if err != nil {
				return err
			}
			// check authentication
			// 1:17 -> :16
			ss_MAC, err := userlib.HMACEval(ss_uuid[:][:16], ss_pac.Marshaled_struct)
			if err != nil {
				return err
			}
			equal := userlib.HMACEqual(ss_MAC, ss_pac.Authentication)
			if !equal {
				err = errors.New("HMAC doesn't match")
				return err
			}
			// decrypt
			if len(ss_pac.Marshaled_struct) < 16 {
				err = errors.New("cipher text length less than 16")
				return err
			}
			ssJSON := userlib.SymDec(ss_uuid[:][:16], ss_pac.Marshaled_struct)
			var ss SharedSpace
			err = json.Unmarshal(ssJSON, &ss)
			if err != nil {
				return err
			}
			// get signkey, symkey and HeadUUID from SharedSpace
			symkey_encrypted := ss.ContentSymkey
			symkey_source, err = userlib.PKEDec(userdata.DecKey, symkey_encrypted)
			if err != nil {
				return err
			}
			headUUID = ss.HeadUUID
			sk = ss.SignKey
		} else {
			// get Head id and keys from File
			symkey_encrypted := oldfile.ContentKey
			symkey_source, err = userlib.PKEDec(userdata.DecKey, symkey_encrypted)
			if err != nil {
				return err
			}
			headUUID = oldfile.HeadUUID
			sk = oldfile.SignKey
		}

		// overwrite the Head Content with new Text, restore to datastore
		// fetch Head
		head_pacJSON, exist := userlib.DatastoreGet(headUUID)
		if !exist {
			err = errors.New("can't find head Content in datastore")
			return err
		}
		symkey_head, err := userlib.HashKDF(symkey_source, headUUID[:])
		if err != nil {
			return err
		}
		symkey_head = symkey_head[:16]
		var head_pac Packet
		err = json.Unmarshal(head_pacJSON, &head_pac)
		if err != nil {
			return err
		}
		vk, exist := userlib.KeystoreGet(headUUID.String() + "DSVerifyKey")
		if !exist {
			err = errors.New("can't find shared verify key for Content in keystore")
			return err
		}
		err = userlib.DSVerify(vk, head_pac.Marshaled_struct, head_pac.Authentication)
		if err != nil {
			return err
		}
		if len(head_pac.Marshaled_struct) < 16 {
			err = errors.New("cipher text length less than 16")
			return err
		}
		headJSON := userlib.SymDec(symkey_head, head_pac.Marshaled_struct)
		var head Content
		err = json.Unmarshal(headJSON, &head)
		if err != nil {
			return err
		}
		head.Text = content
		// restore to datastore
		headJSON, err = json.Marshal(head)
		if err != nil {
			return err
		}
		headJSON_encrypted := userlib.SymEnc(symkey_head, userlib.RandomBytes(16), headJSON)
		head_pac.Marshaled_struct = headJSON_encrypted
		head_sig, err := userlib.DSSign(sk, headJSON_encrypted)
		if err != nil {
			return err
		}
		head_pac.Authentication = head_sig
		head_pacJSON, err = json.Marshal(head_pac)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(headUUID, head_pacJSON)

		// we probably don't need to modify the File or SS struct at all: just the Contents
		// reset the Count.count to 0, restore to datastore
		// fetch the Count
		countUUID, err := uuid.FromBytes(userlib.Hash([]byte(headUUID.String() + "count"))[:16])
		if err != nil {
			return err
		}
		count_pacJSON, exist := userlib.DatastoreGet(countUUID)
		if !exist {
			err = errors.New("can't find Count packet in datastore")
		}
		var count_pac Packet
		err = json.Unmarshal(count_pacJSON, &count_pac)
		if err != nil {
			return err
		}
		verifykey, exist := userlib.KeystoreGet(headUUID.String() + "DSVerifyKey")
		if !exist {
			err = errors.New("can't find verify key for Count")
			return err
		}
		err = userlib.DSVerify(verifykey, count_pac.Marshaled_struct, count_pac.Authentication)
		if err != nil {
			return err
		}
		count_key, err := userlib.HashKDF(symkey_source, countUUID[:])
		if err != nil {
			return err
		}
		count_key = count_key[:16]
		if len(count_pac.Marshaled_struct) < 16 {
			err = errors.New("Cipher text less than 16 bytes")
			return err
		}
		countJSON := userlib.SymDec(count_key, count_pac.Marshaled_struct)
		var count Count
		err = json.Unmarshal(countJSON, &count)
		if err != nil {
			return err
		}
		// save original count for future use
		number := count.Count
		count.Count = 0
		// restore Count
		new_countJSON, err := json.Marshal(count)
		if err != nil {
			return err
		}
		new_countJSON_encrypt := userlib.SymEnc(count_key, userlib.RandomBytes(16), new_countJSON)
		count_sign, err := userlib.DSSign(sk, new_countJSON_encrypt)
		if err != nil {
			return err
		}
		var new_count_pac Packet
		new_count_pac.Authentication = count_sign
		new_count_pac.Marshaled_struct = new_countJSON_encrypt
		new_count_pacJSON, err := json.Marshal(new_count_pac)
		userlib.DatastoreSet(countUUID, new_count_pacJSON)
		// delete the other Contents (iterate through count to get uuid)
		for i := 0; i < number; i++ {
			num := strconv.Itoa(i)
			con_UUID, err := uuid.FromBytes(userlib.Hash([]byte(headUUID.String() + num))[:16])
			if err != nil {
				return err
			}
			_, exist := userlib.DatastoreGet(con_UUID)
			if !exist {
				err = errors.New("can't find Content in datastore")
				return err
			}
			// delete the content by uuid
			userlib.DatastoreDelete(con_UUID)
		}
	}

	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	userdata, err := userptr_helper(userdata.Uuid, userdata.Username)
	if err != nil {
		return err
	}
	// fetch File
	username_string := hex.EncodeToString(userdata.Username)
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + "+" + username_string))[:16])
	if err != nil {
		return err
	}
	file_pacJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		err = errors.New("can't find file in datastore")
		return err
	}
	var file_pac Packet
	err = json.Unmarshal(file_pacJSON, &file_pac)
	if err != nil {
		return err
	}
	file_MAC, exist := userdata.FileMacs[filename]
	if !exist {
		err = errors.New("can't find File's HMAC in userdata")
		return err
	}
	file_HMACkey, err := userlib.HashKDF(userdata.HMACkey, storageKey[:])
	if err != nil {
		return err
	}
	file_HMACkey = file_HMACkey[:16]
	MAC_in_pac, err := userlib.HMACEval(file_HMACkey, file_pac.Marshaled_struct)
	if err != nil {
		return err
	}
	equal := userlib.HMACEqual(MAC_in_pac, file_MAC)
	if !equal {
		err = errors.New("File's HMAC doesn't match")
	}
	if len(file_pac.Marshaled_struct) < 16 {
		err = errors.New("ciphertext length less than 16 bytes")
		return err
	}
	file_symkey_encrypted, exist := userdata.FileKeys[filename]
	if !exist {
		err = errors.New("can't find File encrypted sym key in userdata")
		return err
	}
	file_symkey, err := userlib.PKEDec(userdata.DecKey, file_symkey_encrypted)
	if err != nil {
		return err
	}
	// check if symkey is 16 byte
	if len(file_symkey) != 16 {
		err = errors.New("sym key is not 16 byte")
		return err
	}
	fileJSON := userlib.SymDec(file_symkey, file_pac.Marshaled_struct)
	var file File
	err = json.Unmarshal(fileJSON, &file)
	if err != nil {
		return err
	}
	// check if file matches up?
	if file.Uuid != storageKey {
		err = errors.New("file uuid doesn't match: something is wrong with the File data")
		return err
	}
	// Owned or shared?
	var symkey_source []byte
	var headUUID uuid.UUID
	var sk userlib.DSSignKey
	if file.ContentKey == nil {
		// shared. get SharedSpace
		ss_uuid, exist := userdata.SharedSpaceUUIDs[filename]
		if !exist {
			err = errors.New("can't find ss uuid in userdata")
			return err
		}
		ss_pacJSON, ok := userlib.DatastoreGet(ss_uuid)
		if !ok {
			err = errors.New("can't find data under ss_uuid in datastore")
			return err
		}
		var ss_pac Packet
		err = json.Unmarshal(ss_pacJSON, &ss_pac)
		if err != nil {
			return err
		}
		// check authentication
		// 1:17 -> :16
		ss_MAC, err := userlib.HMACEval(ss_uuid[:][:16], ss_pac.Marshaled_struct)
		if err != nil {
			return err
		}
		equal := userlib.HMACEqual(ss_MAC, ss_pac.Authentication)
		if !equal {
			err = errors.New("HMAC doesn't match")
			return err
		}
		// decrypt
		if len(ss_pac.Marshaled_struct) < 16 {
			err = errors.New("cipher text length less than 16")
			return err
		}
		ssJSON := userlib.SymDec(ss_uuid[:][:16], ss_pac.Marshaled_struct)
		var ss SharedSpace
		err = json.Unmarshal(ssJSON, &ss)
		if err != nil {
			return err
		}
		// get signkey, symkey and HeadUUID from SharedSpace
		symkey_encrypted := ss.ContentSymkey
		symkey_source, err = userlib.PKEDec(userdata.DecKey, symkey_encrypted)
		if err != nil {
			return err
		}
		headUUID = ss.HeadUUID
		sk = ss.SignKey

	} else {
		// owned
		// get signkey and symkey from File
		symkey_encrypted := file.ContentKey
		symkey_source, err = userlib.PKEDec(userdata.DecKey, symkey_encrypted)
		if err != nil {
			return err
		}
		headUUID = file.HeadUUID
		sk = file.SignKey
	}

	// create a new Content
	var con Content
	con.Text = content
	// fetch Count
	countUUID, err := uuid.FromBytes(userlib.Hash([]byte(headUUID.String() + "count"))[:16])
	if err != nil {
		return err
	}
	count_pacJSON, exist := userlib.DatastoreGet(countUUID)
	if !exist {
		err = errors.New("can't find Count packet in datastore")
	}
	var count_pac Packet
	err = json.Unmarshal(count_pacJSON, &count_pac)
	if err != nil {
		return err
	}
	verifykey, exist := userlib.KeystoreGet(headUUID.String() + "DSVerifyKey")
	if !exist {
		err = errors.New("can't find verify key for Count")
		return err
	}
	err = userlib.DSVerify(verifykey, count_pac.Marshaled_struct, count_pac.Authentication)
	if err != nil {
		return err
	}
	count_key, err := userlib.HashKDF(symkey_source, countUUID[:])
	if err != nil {
		return err
	}
	count_key = count_key[:16]
	if len(count_pac.Marshaled_struct) < 16 {
		err = errors.New("Cipher text less than 16 bytes")
		return err
	}
	countJSON := userlib.SymDec(count_key, count_pac.Marshaled_struct)
	var count Count
	err = json.Unmarshal(countJSON, &count)
	if err != nil {
		return err
	}
	// before +1 compute the UUID of the new content
	num := strconv.Itoa(count.Count)
	con_UUID, err := uuid.FromBytes(userlib.Hash([]byte(headUUID.String() + num))[:16])
	if err != nil {
		return err
	}
	// modify the Count to +1
	count.Count = count.Count + 1
	// store Content and Count: file's not modified so no need to re-sign
	// encrypt, sign, store the Count
	new_countJSON, err := json.Marshal(count)
	if err != nil {
		return err
	}
	new_countJSON_encrypt := userlib.SymEnc(count_key, userlib.RandomBytes(16), new_countJSON)
	count_sign, err := userlib.DSSign(sk, new_countJSON_encrypt)
	if err != nil {
		return err
	}
	var new_count_pac Packet
	new_count_pac.Authentication = count_sign
	new_count_pac.Marshaled_struct = new_countJSON_encrypt
	new_count_pacJSON, err := json.Marshal(new_count_pac)
	userlib.DatastoreSet(countUUID, new_count_pacJSON)
	// encrypt, sign, store the Content
	conJSON, err := json.Marshal(con)
	if err != nil {
		return err
	}
	con_symkey, err := userlib.HashKDF(symkey_source, con_UUID[:])
	if err != nil {
		return err
	}
	con_symkey = con_symkey[:16]
	conJSON_encrypted := userlib.SymEnc(con_symkey, userlib.RandomBytes(16), conJSON)
	con_sign, err := userlib.DSSign(sk, conJSON_encrypted)
	if err != nil {
		return err
	}
	var con_pac Packet
	con_pac.Authentication = con_sign
	con_pac.Marshaled_struct = conJSON_encrypted
	con_pacJSON, err := json.Marshal(con_pac)
	userlib.DatastoreSet(con_UUID, con_pacJSON)
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	userdata, err = userptr_helper(userdata.Uuid, userdata.Username)
	if err != nil {
		return nil, err
	}
	username_string := hex.EncodeToString(userdata.Username)
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + "+" + username_string))[:16])
	if err != nil {
		return nil, err
	}

	// load the File struct
	file_pacJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		err = errors.New("can't find file in datastore")
		return nil, err
	}
	var file_pac Packet
	err = json.Unmarshal(file_pacJSON, &file_pac)
	if err != nil {
		return nil, err
	}
	file_MAC, exist := userdata.FileMacs[filename]
	if !exist {
		err = errors.New("can't find File's HMAC in userdata")
		return nil, err
	}
	file_HMACkey, err := userlib.HashKDF(userdata.HMACkey, storageKey[:])
	if err != nil {
		return nil, err
	}
	file_HMACkey = file_HMACkey[:16]
	MAC_in_pac, err := userlib.HMACEval(file_HMACkey, file_pac.Marshaled_struct)
	if err != nil {
		return nil, err
	}
	equal := userlib.HMACEqual(MAC_in_pac, file_MAC)
	if !equal {
		err = errors.New("File's HMAC doesn't match")
	}
	if len(file_pac.Marshaled_struct) < 16 {
		err = errors.New("ciphertext length less than 16 bytes")
		return nil, err
	}
	// note: even if file is shared, user has their own head File
	file_symkey_encrypted, exist := userdata.FileKeys[filename]
	if !exist {
		err = errors.New("can't find File encrypted sym key in userdata")
		return nil, err
	}
	file_symkey, err := userlib.PKEDec(userdata.DecKey, file_symkey_encrypted)
	if err != nil {
		return nil, err
	}
	// check if symkey is 16 byte
	if len(file_symkey) != 16 {
		err = errors.New("sym key is not 16 byte")
		return nil, err
	}
	fileJSON := userlib.SymDec(file_symkey, file_pac.Marshaled_struct)
	var file File
	err = json.Unmarshal(fileJSON, &file)
	if err != nil {
		return nil, err
	}
	// check if file matches up?
	if file.Uuid != storageKey {
		err = errors.New("file uuid doesn't match: something is wrong with the File data")
		return nil, err
	}

	// check whether user owns the File or is shared or is revoked:

	// (need to define variables outside)
	var symkey_source []byte
	var headUUID uuid.UUID
	//var signkey userlib.DSSignKey
	// see if File.SignKey or sth is nil
	if file.ContentKey == nil {
		//own = false
		// if nil: shared. find the SharedSpace UUID in User
		ss_uuid, exist := userdata.SharedSpaceUUIDs[filename]
		if !exist {
			err = errors.New("can't find sharedSpace uuid in userdata")
			return nil, err
		}
		// get SharedSpace from datastore: if fail, then access is probably revoked
		ss_pacJSON, exist := userlib.DatastoreGet(ss_uuid)
		if !exist {
			err = errors.New("can't find sharedSpace in datastore, access is probably revoked")
			return nil, err
		}
		// proceed if ss exists. load the ss struct
		var ss_pac Packet
		err = json.Unmarshal(ss_pacJSON, &ss_pac)
		if err != nil {
			return nil, err
		}
		// ownername, exist := userdata.SharedSpaceOwners[filename]
		// if !exist {
		// 	err = errors.New("can't find owner name in userdata")
		// 	return nil, err
		// }
		// owner_vk, ok := userlib.KeystoreGet(hex.EncodeToString(ownername) + "DSVerifyKey")
		// if !ok {
		// 	err = errors.New("can't find sender's signature verify key in keystore")
		// 	return nil, err
		// }
		// err = userlib.DSVerify(owner_vk, ss_pac.Marshaled_struct, ss_pac.Authentication)
		// if err != nil {
		// 	return nil, err
		// }
		// 1:17 -> :16
		ss_MAC, err := userlib.HMACEval(ss_uuid[:][:16], ss_pac.Marshaled_struct)
		if err != nil {
			return nil, err
		}
		equal := userlib.HMACEqual(ss_MAC, ss_pac.Authentication)
		if !equal {
			err = errors.New("HMAC doesn't match")
			return nil, err
		}
		if len(ss_pac.Marshaled_struct) < 16 {
			err = errors.New("cipher text length less than 16")
			return nil, err
		}
		ssJSON := userlib.SymDec(ss_uuid[:][:16], ss_pac.Marshaled_struct)
		var ss SharedSpace
		err = json.Unmarshal(ssJSON, &ss)
		if err != nil {
			return nil, err
		}
		// get signkey, symkey and HeadUUID from SharedSpace
		symkey_encrypted := ss.ContentSymkey
		symkey_source, err = userlib.PKEDec(userdata.DecKey, symkey_encrypted)
		if err != nil {
			return nil, err
		}
		// (we are just accessing, not modifying so no need for sign key?)
		//signkey = ss.SignKey
		headUUID = ss.HeadUUID
	} else {
		// own file, get signkey, symkey and HeadUUID from File
		symkey_encrypted := file.ContentKey
		symkey_source, err = userlib.PKEDec(userdata.DecKey, symkey_encrypted)
		if err != nil {
			return nil, err
		}
		//signkey = file.SignKey
		headUUID = file.HeadUUID
	}

	// fetch the head (datastoreGet process)
	head_pacJSON, exist := userlib.DatastoreGet(headUUID)
	if !exist {
		err = errors.New("can't find head Content in datastore")
		return nil, err
	}
	symkey_head, err := userlib.HashKDF(symkey_source, headUUID[:])
	if err != nil {
		return nil, err
	}
	symkey_head = symkey_head[:16]
	var head_pac Packet
	err = json.Unmarshal(head_pacJSON, &head_pac)
	if err != nil {
		return nil, err
	}
	vk, exist := userlib.KeystoreGet(headUUID.String() + "DSVerifyKey")
	if !exist {
		err = errors.New("can't find shared verify key for Content in keystore")
		return nil, err
	}
	err = userlib.DSVerify(vk, head_pac.Marshaled_struct, head_pac.Authentication)
	if err != nil {
		return nil, err
	}
	if len(head_pac.Marshaled_struct) < 16 {
		err = errors.New("cipher text length less than 16")
		return nil, err
	}
	headJSON := userlib.SymDec(symkey_head, head_pac.Marshaled_struct)
	var head Content
	err = json.Unmarshal(headJSON, &head)
	if err != nil {
		return nil, err
	}
	// get the first Text
	content = head.Text
	// fetch the Count (datastoreGet)
	count_uuid, err := uuid.FromBytes(userlib.Hash([]byte(headUUID.String() + "count"))[:16])
	count_pacJSON, exist := userlib.DatastoreGet(count_uuid)
	if !exist {
		err = errors.New("can't find Count in datastore")
		return nil, err
	}
	var count_pac Packet
	err = json.Unmarshal(count_pacJSON, &count_pac)
	if err != nil {
		return nil, err
	}
	err = userlib.DSVerify(vk, count_pac.Marshaled_struct, count_pac.Authentication)
	if err != nil {
		return nil, err
	}
	count_key, err := userlib.HashKDF(symkey_source, count_uuid[:])
	if err != nil {
		return nil, err
	}
	count_key = count_key[:16]
	if len(count_pac.Marshaled_struct) < 16 {
		err = errors.New("Cipher text less than 16 bytes")
		return nil, err
	}
	countJSON := userlib.SymDec(count_key, count_pac.Marshaled_struct)
	var count Count
	err = json.Unmarshal(countJSON, &count)
	if err != nil {
		return nil, err
	}
	// iterate through the Contents (i<count or sth) (datastoreGet), append the Text
	for i := 0; i < count.Count; i++ {
		num := strconv.Itoa(i)
		con_UUID, err := uuid.FromBytes(userlib.Hash([]byte(headUUID.String() + num))[:16])
		if err != nil {
			return nil, err
		}
		con_pacJSON, exist := userlib.DatastoreGet(con_UUID)
		if !exist {
			err = errors.New("can't find Content in datastore")
			return nil, err
		}
		var con_pac Packet
		err = json.Unmarshal(con_pacJSON, &con_pac)
		if err != nil {
			return nil, err
		}
		err = userlib.DSVerify(vk, con_pac.Marshaled_struct, con_pac.Authentication)
		if err != nil {
			return nil, err
		}
		if len(con_pac.Marshaled_struct) < 16 {
			err = errors.New("cipher text length less than 16 bytes")
			return nil, err
		}
		con_key, err := userlib.HashKDF(symkey_source, con_UUID[:])
		if err != nil {
			return nil, err
		}
		con_key = con_key[:16]
		conJSON := userlib.SymDec(con_key, con_pac.Marshaled_struct)
		var con Content
		err = json.Unmarshal(conJSON, &con)
		if err != nil {
			return nil, err
		}
		content = append(content, con.Text...)
	}
	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	userdata, err = userptr_helper(userdata.Uuid, userdata.Username)
	if err != nil {
		return uuid.Nil, err
	}
	username_string := hex.EncodeToString(userdata.Username)
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + "+" + username_string))[:16])
	if err != nil {
		return uuid.Nil, err
	}
	// see if the filename exist in userspace
	var file_pac Packet
	var file File
	file_pacJSON, exist := userlib.DatastoreGet(storageKey)
	if !exist {
		err = errors.New("user doesn't have the file")
		return uuid.Nil, err
	}
	err = json.Unmarshal(file_pacJSON, &file_pac)
	if err != nil {
		return uuid.Nil, err
	}
	// check authentication, HMAC
	MAC_in_user, exists := userdata.FileMacs[filename]
	if !exists {
		err = errors.New("user doesn't have the HMAC for File")
		return uuid.Nil, err
	}
	file_HMACkey, err := userlib.HashKDF(userdata.HMACkey, storageKey[:])
	if err != nil {
		return uuid.Nil, err
	}
	file_HMACkey = file_HMACkey[:16]
	MAC_in_pac, err := userlib.HMACEval(file_HMACkey, file_pac.Marshaled_struct)
	if err != nil {
		return uuid.Nil, err
	}
	equal := userlib.HMACEqual(MAC_in_pac, MAC_in_user)
	if !equal {
		err = errors.New("no.1 HMAC doesn't match.")
		return uuid.Nil, err
	}
	// symmetric decrypt with FileKey from User
	if len(file_pac.Marshaled_struct) < 16 {
		err = errors.New("ciphertext less than 16 bytes")
		return uuid.Nil, err
	}
	file_symkey_encrypted, exists := userdata.FileKeys[filename]
	if !exists {
		err = errors.New("user doesn't have the sym key for File")
		return uuid.Nil, err
	}
	file_symkey, err := userlib.PKEDec(userdata.DecKey, file_symkey_encrypted)
	if err != nil {
		return uuid.Nil, err
	}
	fileJSON := userlib.SymDec(file_symkey, file_pac.Marshaled_struct)
	// unmarshal, now we have the actual File
	err = json.Unmarshal(fileJSON, &file)
	if err != nil {
		return uuid.Nil, err
	}
	// check filename
	filename_equal := userlib.HMACEqual(userlib.Hash([]byte(filename)), file.Filename)
	if !filename_equal {
		err = errors.New("something wrong with unmarshaled File")
		return uuid.Nil, err
	}
	var symkey_source []byte
	var headUUID uuid.UUID
	var sk userlib.DSSignKey
	var own bool
	if file.ContentKey == nil {
		// shared. get SharedSpace
		own = false
		ss_uuid, exist := userdata.SharedSpaceUUIDs[filename]
		if !exist {
			err = errors.New("can't find ss uuid in userdata")
			return uuid.Nil, err
		}
		ss_pacJSON, ok := userlib.DatastoreGet(ss_uuid)
		if !ok {
			err = errors.New("can't find data under ss_uuid in datastore")
			return uuid.Nil, err
		}
		var ss_pac Packet
		err = json.Unmarshal(ss_pacJSON, &ss_pac)
		if err != nil {
			return uuid.Nil, err
		}
		// check authentication
		// 1:17 -> :16
		ss_MAC, err := userlib.HMACEval(ss_uuid[:][:16], ss_pac.Marshaled_struct)
		if err != nil {
			return uuid.Nil, err
		}
		equal := userlib.HMACEqual(ss_MAC, ss_pac.Authentication)
		if !equal {
			err = errors.New("no.2 HMAC doesn't match")
			return uuid.Nil, err
		}
		// decrypt
		if len(ss_pac.Marshaled_struct) < 16 {
			err = errors.New("cipher text length less than 16")
			return uuid.Nil, err
		}
		ssJSON := userlib.SymDec(ss_uuid[:][:16], ss_pac.Marshaled_struct)
		var ss SharedSpace
		err = json.Unmarshal(ssJSON, &ss)
		if err != nil {
			return uuid.Nil, err
		}
		// get signkey, symkey and HeadUUID from SharedSpace
		symkey_encrypted := ss.ContentSymkey
		symkey_source, err = userlib.PKEDec(userdata.DecKey, symkey_encrypted)
		if err != nil {
			return uuid.Nil, err
		}
		headUUID = ss.HeadUUID
		sk = ss.SignKey

	} else {
		// owned
		own = true
		// get signkey and symkey from File
		symkey_encrypted := file.ContentKey
		symkey_source, err = userlib.PKEDec(userdata.DecKey, symkey_encrypted)
		if err != nil {
			return uuid.Nil, err
		}
		headUUID = file.HeadUUID
		sk = file.SignKey
	}
	// create invitation
	var invitation Invitation
	// re-encrypt sym source key for Contents
	content_symkey := symkey_source
	hashedRecipientName := userlib.Hash([]byte(recipientUsername))
	recipientEncKey, exist := userlib.KeystoreGet(hex.EncodeToString(hashedRecipientName) + "PKEEncKey")
	if !exist {
		err = errors.New("recipient's public EncKey doesn't exist")
		return uuid.Nil, err
	}
	content_new_symkey, err := userlib.PKEEnc(recipientEncKey, content_symkey)
	if err != nil {
		return uuid.Nil, err
	}
	//invitation.Symkey = content_new_symkey
	// HMACkey
	//invitation.HMACkey = file.HMACkey
	// SignKey
	//invitation.SK = sk
	// first Content uuid
	//invitation.Head = headUUID
	// SharedSpaceUUID
	sharedSpace_uuid, err := uuid.FromBytes(userlib.RandomBytes(16))
	if err != nil {
		return uuid.Nil, err
	}
	invitation.SSUUID = sharedSpace_uuid
	// create the sharedSpace
	var shared_space SharedSpace
	shared_space.ContentSymkey = content_new_symkey
	shared_space.HeadUUID = headUUID
	//shared_space.HMACkey = file.HMACkey
	shared_space.SignKey = sk
	//var uuid_array []uuid.UUID
	shared_space.SharedSpaceUUIDs = make(map[string]uuid.UUID)
	// store the sharedSpace in datastore, uuid is sharedSpace_uuid
	sharedSpaceJSON, err := json.Marshal(shared_space)
	if err != nil {
		return uuid.Nil, err
	}
	encrypted_JSON := userlib.SymEnc(sharedSpace_uuid[:][:16], userlib.RandomBytes(16), sharedSpaceJSON)
	var ss_pac Packet
	ss_pac.Marshaled_struct = encrypted_JSON
	// signature, err := userlib.DSSign(userdata.SignKey, encrypted_JSON)
	// if err != nil {
	// 	return uuid.Nil, err
	// }
	// 1:17 -> :16
	ss_HMAC, err := userlib.HMACEval(sharedSpace_uuid[:][:16], encrypted_JSON)
	if err != nil {
		return uuid.Nil, err
	}
	ss_pac.Authentication = ss_HMAC
	ss_pacJSON, err := json.Marshal(ss_pac)
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(sharedSpace_uuid, ss_pacJSON)
	if own == true {
		// update file's sharedWith
		file.SharedWith[recipientUsername] = sharedSpace_uuid
		// restore the file
		new_fileJSON, err := json.Marshal(file)
		if err != nil {
			return uuid.Nil, err
		}
		new_fileJSON_encrypt := userlib.SymEnc(file_symkey, userlib.RandomBytes(16), new_fileJSON)
		new_file_HMACkey, err := userlib.HashKDF(userdata.HMACkey, storageKey[:])
		if err != nil {
			return uuid.Nil, err
		}
		new_fileMAC, err := userlib.HMACEval(new_file_HMACkey[:16], new_fileJSON_encrypt)
		if err != nil {
			return uuid.Nil, err
		}
		file_pac.Authentication = new_fileMAC
		file_pac.Marshaled_struct = new_fileJSON_encrypt
		file_pacJSON, err = json.Marshal(file_pac)
		if err != nil {
			return uuid.Nil, err
		}
		userlib.DatastoreSet(storageKey, file_pacJSON)

		// update and restore the userdata <- fileMAC
		userdata.FileMacs[filename] = new_fileMAC
		userJSON, err := json.Marshal(userdata)
		if err != nil {
			return uuid.Nil, err
		}
		userJSON_encrypt := userlib.SymEnc(userdata.Uuid[:][:16], userlib.RandomBytes(16), userJSON)
		user_signature, err := userlib.DSSign(userdata.SignKey, userJSON_encrypt)
		if err != nil {
			return uuid.Nil, err
		}
		var user_pac Packet
		user_pac.Authentication = user_signature
		user_pac.Marshaled_struct = userJSON_encrypt
		user_pacJSON, err := json.Marshal(user_pac)
		if err != nil {
			return uuid.Nil, err
		}
		userlib.DatastoreSet(userdata.Uuid, user_pacJSON)
	} else {
		caller_ss_uuid, exist := userdata.SharedSpaceUUIDs[filename]
		if !exist {
			err = errors.New("can't find ss uuid in userdata")
			return uuid.Nil, err
		}
		caller_ss_pacJSON, ok := userlib.DatastoreGet(caller_ss_uuid)
		if !ok {
			err = errors.New("can't find data under ss_uuid in datastore")
			return uuid.Nil, err
		}
		var caller_ss_pac Packet
		err = json.Unmarshal(caller_ss_pacJSON, &caller_ss_pac)
		if err != nil {
			return uuid.Nil, err
		}
		// check authentication
		// 1:17 -> :16
		caller_ss_MAC, err := userlib.HMACEval(caller_ss_uuid[:][:16], caller_ss_pac.Marshaled_struct)
		if err != nil {
			return uuid.Nil, err
		}
		equal := userlib.HMACEqual(caller_ss_MAC, caller_ss_pac.Authentication)
		if !equal {
			err = errors.New("no.3 HMAC doesn't match")
			return uuid.Nil, err
		}
		// decrypt
		if len(caller_ss_pac.Marshaled_struct) < 16 {
			err = errors.New("cipher text length less than 16")
			return uuid.Nil, err
		}
		caller_ssJSON := userlib.SymDec(caller_ss_uuid[:][:16], caller_ss_pac.Marshaled_struct)
		var caller_ss SharedSpace
		err = json.Unmarshal(caller_ssJSON, &caller_ss)
		if err != nil {
			return uuid.Nil, err
		}
		caller_ss.SharedSpaceUUIDs[recipientUsername] = sharedSpace_uuid
		// store caller_ss
		new_ssJSON, err := json.Marshal(caller_ss)
		if err != nil {
			return uuid.Nil, err
		}
		ssJSON_encrypt := userlib.SymEnc(caller_ss_uuid[:][:16], userlib.RandomBytes(16), new_ssJSON)
		// 1:17 -> :16
		newMAC, err := userlib.HMACEval(caller_ss_uuid[:][:16], ssJSON_encrypt)
		if err != nil {
			return uuid.Nil, err
		}
		var new_ss_pac Packet
		new_ss_pac.Authentication = newMAC
		new_ss_pac.Marshaled_struct = ssJSON_encrypt
		new_ss_pacJSON, err := json.Marshal(new_ss_pac)
		if err != nil {
			return uuid.Nil, err
		}
		userlib.DatastoreSet(caller_ss_uuid, new_ss_pacJSON)
	}

	// store the invitation, return its uuid
	invitationJSON, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, err
	}
	encrypted_invitation_JSON, err := userlib.PKEEnc(recipientEncKey, invitationJSON)
	if err != nil {
		return uuid.Nil, err
	}
	var invitation_pac Packet
	invitation_pac.Marshaled_struct = encrypted_invitation_JSON
	invitation_signature, err := userlib.DSSign(userdata.SignKey, encrypted_invitation_JSON)
	if err != nil {
		return uuid.Nil, err
	}
	invitation_pac.Authentication = invitation_signature
	invitation_pacJSON, err := json.Marshal(invitation_pac)
	if err != nil {
		return uuid.Nil, err
	}
	invitation_uuid, err := uuid.FromBytes(userlib.Hash([]byte(username_string + filename + recipientUsername))[:16])
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(invitation_uuid, invitation_pacJSON)

	// [[[[[if caller is not owner of File!!!!!]]]]]
	return invitation_uuid, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	userdata, err := userptr_helper(userdata.Uuid, userdata.Username)
	if err != nil {
		return err
	}
	// fetch invitation from datastore
	invitation_pacJSON, exist := userlib.DatastoreGet(invitationPtr)
	if !exist {
		err := errors.New("can't find invitation in datastore")
		return err
	}
	var invitation_pac Packet
	err = json.Unmarshal(invitation_pacJSON, &invitation_pac)
	if err != nil {
		return err
	}
	hashedSenderName := userlib.Hash([]byte(senderUsername))
	sender_vk, ok := userlib.KeystoreGet(hex.EncodeToString(hashedSenderName) + "DSVerifyKey")
	if !ok {
		err = errors.New("can't find sender's signature verify key in keystore")
		return err
	}
	err = userlib.DSVerify(sender_vk, invitation_pac.Marshaled_struct, invitation_pac.Authentication)
	if err != nil {
		return err
	}
	invitationJSON, err := userlib.PKEDec(userdata.DecKey, invitation_pac.Marshaled_struct)
	if err != nil {
		return err
	}
	var invitation Invitation
	err = json.Unmarshal(invitationJSON, &invitation)
	if err != nil {
		return err
	}
	// create new File
	var file File
	hashedFilename := userlib.Hash([]byte(filename))
	file.Filename = hashedFilename
	username_string := hex.EncodeToString(userdata.Username)
	file_uuid, err := uuid.FromBytes(userlib.Hash([]byte(filename + "+" + username_string))[:16])
	if err != nil {
		return err
	}
	// check if filename is taken
	_, exist = userlib.DatastoreGet(file_uuid)
	if exist {
		err = errors.New(fmt.Sprintf("filename %s is already taken for user", filename))
		return err
	}
	file.Uuid = file_uuid
	file.SharedWith = make(map[string]uuid.UUID)
	// store the new File
	fileJSON, err := json.Marshal(file)
	if err != nil {
		return err
	}
	// generate random sym key for file encryption
	file_symkey := userlib.RandomBytes(16)
	// encrypt fileJSON using symkey
	fileJSON_encrypt := userlib.SymEnc(file_symkey, userlib.RandomBytes(16), fileJSON)
	var file_pac Packet
	file_pac.Marshaled_struct = fileJSON_encrypt
	// compute the HMAC key for File
	file_HMACkey, err := userlib.HashKDF(userdata.HMACkey, file_uuid[:])
	if err != nil {
		return err
	}
	file_HMAC, err := userlib.HMACEval(file_HMACkey[:16], fileJSON_encrypt)
	if err != nil {
		return err
	}
	file_pac.Authentication = file_HMAC
	file_pacJSON, err := json.Marshal(file_pac)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(file_uuid, file_pacJSON)
	// update fileKeys and fileMACs to include the new File in User
	userdata.FileMacs[filename] = file_HMAC
	// encrypt file_symkey with public key
	user_EncKey, exist := userlib.KeystoreGet(hex.EncodeToString(userdata.Username) + "PKEEncKey")
	if !exist {
		err = errors.New("can't find user's EncKey in key_store")
		return err
	}
	file_symkey_encrypted, err := userlib.PKEEnc(user_EncKey, file_symkey)
	if err != nil {
		return err
	}
	userdata.FileKeys[filename] = file_symkey_encrypted
	// store UUID of sharedSpace in userdata
	// check if ss still exist?
	_, exist = userlib.DatastoreGet(invitation.SSUUID)
	if !exist {
		err = errors.New("can't find sharedSpace in datastore")
		return err
	}
	userdata.SharedSpaceUUIDs[filename] = invitation.SSUUID
	// store owner of sharedSpace in userdata
	//userdata.SharedSpaceOwners[filename] = hashedSenderName
	// restore the User
	userJSON, err := json.Marshal(userdata)
	if err != nil {
		return err
	}
	userJSON_encrypt := userlib.SymEnc(userdata.Uuid[:][:16], userlib.RandomBytes(16), userJSON)
	user_signature, err := userlib.DSSign(userdata.SignKey, userJSON_encrypt)
	if err != nil {
		return err
	}
	var user_pac Packet
	user_pac.Marshaled_struct = userJSON_encrypt
	user_pac.Authentication = user_signature
	user_pacJSON, err := json.Marshal(user_pac)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(userdata.Uuid, user_pacJSON)
	// delete the invitation
	userlib.DatastoreDelete(invitationPtr)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	userdata, err := userptr_helper(userdata.Uuid, userdata.Username)
	if err != nil {
		return err
	}
	// check if user have access: actually no need to implement. undefined behavior
	// fetch the File
	username_string := hex.EncodeToString(userdata.Username)
	file_uuid, err := uuid.FromBytes(userlib.Hash([]byte(filename + "+" + username_string))[:16])
	if err != nil {
		return err
	}
	// see if the filename exist in userspace
	var file_pac Packet
	var file File
	file_pacJSON, exist := userlib.DatastoreGet(file_uuid)
	if !exist {
		err = errors.New("user doesn't have the file")
		return err
	}
	err = json.Unmarshal(file_pacJSON, &file_pac)
	if err != nil {
		return err
	}
	// check authentication, HMAC
	MAC_in_user, exists := userdata.FileMacs[filename]
	if !exists {
		err = errors.New("user doesn't have the HMAC for File")
		return err
	}
	file_HMACkey, err := userlib.HashKDF(userdata.HMACkey, file_uuid[:])
	if err != nil {
		return err
	}
	file_HMACkey = file_HMACkey[:16]
	MAC_in_pac, err := userlib.HMACEval(file_HMACkey, file_pac.Marshaled_struct)
	if err != nil {
		return err
	}
	equal := userlib.HMACEqual(MAC_in_pac, MAC_in_user)
	if !equal {
		err = errors.New("HMAC doesn't match.")
		return err
	}
	// symmetric decrypt with FileKey from User
	if len(file_pac.Marshaled_struct) < 16 {
		err = errors.New("ciphertext less than 16 bytes")
		return err
	}
	file_symkey_encrypted, exists := userdata.FileKeys[filename]
	if !exists {
		err = errors.New("user doesn't have the sym key for File")
		return err
	}
	file_symkey, err := userlib.PKEDec(userdata.DecKey, file_symkey_encrypted)
	if err != nil {
		return err
	}
	fileJSON := userlib.SymDec(file_symkey, file_pac.Marshaled_struct)
	// unmarshal, now we have the actual File
	err = json.Unmarshal(fileJSON, &file)
	if err != nil {
		return err
	}
	// check filename
	filename_equal := userlib.HMACEqual(userlib.Hash([]byte(filename)), file.Filename)
	if !filename_equal {
		err = errors.New("something wrong with unmarshaled File")
		return err
	}
	// find the SharedSpace, delete it
	ss_uuid, ok := file.SharedWith[recipientUsername]
	if !ok {
		err = errors.New("can't find SharedSpace with recipient uuid in File")
		return err
	}
	userlib.DatastoreDelete(ss_uuid)
	// [[[[if recipient's shared the file with others, delete those SharedSpace too]]]]] necessary?

	// delete it from File's (filename) SharedWith
	delete(file.SharedWith, recipientUsername)
	// keep old uuid in record
	old_headUUID := file.HeadUUID
	// regenerate UUID for head Content <- update user's File
	new_headUUID, err := uuid.FromBytes(userlib.RandomBytes(16))
	if err != nil {
		return err
	}
	file.HeadUUID = new_headUUID
	// regenerate sym key and SignKey <- should be updated in user's File, all effective SharedSpace
	new_symkey_source := userlib.RandomBytes(16)
	userEncKey, exist := userlib.KeystoreGet(hex.EncodeToString(userdata.Username) + "PKEEncKey")
	if !exist {
		err = errors.New("can't find user's EncKey in keystore")
		return err
	}
	file_encrypt_symkey, err := userlib.PKEEnc(userEncKey, new_symkey_source)
	if err != nil {
		return err
	}
	// keep the old sym key in record
	symkey_encrypted := file.ContentKey
	old_symkey_source, err := userlib.PKEDec(userdata.DecKey, symkey_encrypted)
	if err != nil {
		return err
	}
	// overwrite old sym key with new sym key (encrypted)
	file.ContentKey = file_encrypt_symkey
	new_signkey, new_verifykey, err := userlib.DSKeyGen()
	if err != nil {
		return err
	}
	// overwrite old signkey with new signkey
	file.SignKey = new_signkey
	// keep the old verify key
	old_verifykey, exist := userlib.KeystoreGet(old_headUUID.String() + "DSVerifyKey")
	if !exist {
		err = errors.New("can't find verify key for Contents")
		return err
	}
	// save new verify key in keystore (uuid's different now)
	err = userlib.KeystoreSet(new_headUUID.String()+"DSVerifyKey", new_verifykey)
	if err != nil {
		return err
	}
	// re-encrypt and regenerate signature for Count <- compute new UUID!
	// casting headUUID+"count" to new UUID
	old_countUUID, err := uuid.FromBytes(userlib.Hash([]byte(old_headUUID.String() + "count"))[:16])
	if err != nil {
		return err
	}
	old_count_pacJSON, exist := userlib.DatastoreGet(old_countUUID)
	if !exist {
		err = errors.New("can't find Count packet in datastore")
	}
	var old_count_pac Packet
	err = json.Unmarshal(old_count_pacJSON, &old_count_pac)
	if err != nil {
		return err
	}
	err = userlib.DSVerify(old_verifykey, old_count_pac.Marshaled_struct, old_count_pac.Authentication)
	if err != nil {
		return err
	}
	old_count_key, err := userlib.HashKDF(old_symkey_source, old_countUUID[:])
	if err != nil {
		return err
	}
	old_count_key = old_count_key[:16]
	if len(old_count_pac.Marshaled_struct) < 16 {
		err = errors.New("Cipher text less than 16 bytes")
		return err
	}
	countJSON := userlib.SymDec(old_count_key, old_count_pac.Marshaled_struct)
	// re-encrypt and sign don't need to modify the actual Count struct, but we need the Count.count
	var count Count
	err = json.Unmarshal(countJSON, &count)
	if err != nil {
		return err
	}
	// re-encrypting countJSON
	new_countUUID, err := uuid.FromBytes(userlib.Hash([]byte(new_headUUID.String() + "count"))[:16])
	if err != nil {
		return err
	}
	new_count_key, err := userlib.HashKDF(new_symkey_source, new_countUUID[:])
	if err != nil {
		return err
	}
	new_count_key = new_count_key[:16]
	countJSON_encrypted := userlib.SymEnc(new_count_key, userlib.RandomBytes(16), countJSON)
	countJSON_sign, err := userlib.DSSign(new_signkey, countJSON_encrypted)
	if err != nil {
		return err
	}
	var new_count_pac Packet
	new_count_pac.Authentication = countJSON_sign
	new_count_pac.Marshaled_struct = countJSON_encrypted
	new_count_pacJSON, err := json.Marshal(new_count_pac)
	if err != nil {
		return err
	}
	// delete old Count
	userlib.DatastoreDelete(old_countUUID)
	// set new Count in datastore
	userlib.DatastoreSet(new_countUUID, new_count_pacJSON)

	// re-encrypt and regenerate signature for Contents (for loop?)
	for i := 0; i < count.Count; i++ {
		// fetching the old pacs, verify and decrypt with old keys
		num := strconv.Itoa(i)
		old_con_UUID, err := uuid.FromBytes(userlib.Hash([]byte(old_headUUID.String() + num))[:16])
		if err != nil {
			return err
		}
		old_con_pacJSON, exist := userlib.DatastoreGet(old_con_UUID)
		if !exist {
			err = errors.New("can't find Content in datastore")
			return err
		}
		var old_con_pac Packet
		err = json.Unmarshal(old_con_pacJSON, &old_con_pac)
		if err != nil {
			return err
		}
		err = userlib.DSVerify(old_verifykey, old_con_pac.Marshaled_struct, old_con_pac.Authentication)
		if err != nil {
			return err
		}
		if len(old_con_pac.Marshaled_struct) < 16 {
			err = errors.New("cipher text length less than 16 bytes")
			return err
		}
		old_con_key, err := userlib.HashKDF(old_symkey_source, old_con_UUID[:])
		if err != nil {
			return err
		}
		old_con_key = old_con_key[:16]
		conJSON := userlib.SymDec(old_con_key, old_con_pac.Marshaled_struct)
		// don't need to unmarshal the Content
		// re-encrypt and sign with new keys
		new_con_UUID, err := uuid.FromBytes(userlib.Hash([]byte(new_headUUID.String() + num))[:16])
		if err != nil {
			return err
		}
		new_con_key, err := userlib.HashKDF(new_symkey_source, new_con_UUID[:])
		if err != nil {
			return err
		}
		new_con_key = new_con_key[:16]
		conJSON_encrypted := userlib.SymEnc(new_con_key, userlib.RandomBytes(16), conJSON)
		conJSON_sign, err := userlib.DSSign(new_signkey, conJSON_encrypted)
		if err != nil {
			return err
		}
		var new_con_pac Packet
		new_con_pac.Marshaled_struct = conJSON_encrypted
		new_con_pac.Authentication = conJSON_sign
		new_con_pacJSON, err := json.Marshal(new_con_pac)
		if err != nil {
			return err
		}
		// delete old Contents with old UUID and store new Contents with new UUID
		userlib.DatastoreDelete(old_con_UUID)
		userlib.DatastoreSet(new_con_UUID, new_con_pacJSON)
	}
	// we haven't restored the Head
	old_head_pacJSON, exist := userlib.DatastoreGet(old_headUUID)
	if !exist {
		err = errors.New("can't find Content in datastore")
		return err
	}
	var old_head_pac Packet
	err = json.Unmarshal(old_head_pacJSON, &old_head_pac)
	if err != nil {
		return err
	}
	err = userlib.DSVerify(old_verifykey, old_head_pac.Marshaled_struct, old_head_pac.Authentication)
	if err != nil {
		return err
	}
	if len(old_head_pac.Marshaled_struct) < 16 {
		err = errors.New("cipher text length less than 16 bytes")
		return err
	}
	old_head_key, err := userlib.HashKDF(old_symkey_source, old_headUUID[:])
	if err != nil {
		return err
	}
	old_head_key = old_head_key[:16]
	headJSON := userlib.SymDec(old_head_key, old_head_pac.Marshaled_struct)
	// don't need to unmarshal the Content
	// re-encrypt and sign with new keys
	new_head_key, err := userlib.HashKDF(new_symkey_source, new_headUUID[:])
	if err != nil {
		return err
	}
	new_head_key = new_head_key[:16]
	headJSON_encrypted := userlib.SymEnc(new_head_key, userlib.RandomBytes(16), headJSON)
	headJSON_sign, err := userlib.DSSign(new_signkey, headJSON_encrypted)
	if err != nil {
		return err
	}
	var new_head_pac Packet
	new_head_pac.Marshaled_struct = headJSON_encrypted
	new_head_pac.Authentication = headJSON_sign
	new_head_pacJSON, err := json.Marshal(new_head_pac)
	if err != nil {
		return err
	}
	// delete old Contents with old UUID and store new Contents with new UUID
	userlib.DatastoreDelete(old_headUUID)
	userlib.DatastoreSet(new_headUUID, new_head_pacJSON)

	// restore File of User
	new_fileJSON, err := json.Marshal(file)
	if err != nil {
		return err
	}
	new_fileJSON_encrypt := userlib.SymEnc(file_symkey, userlib.RandomBytes(16), new_fileJSON)
	file_hashkey, err := userlib.HashKDF(userdata.HMACkey, []byte(filename))
	if err != nil {
		return err
	}
	file_hashkey = file_hashkey[:16]
	new_fileJSON_HMAC, err := userlib.HMACEval(file_hashkey, new_fileJSON_encrypt)
	if err != nil {
		return err
	}
	var new_file_pac Packet
	new_file_pac.Authentication = new_fileJSON_HMAC
	new_file_pac.Marshaled_struct = new_fileJSON_encrypt
	new_file_pacJSON, err := json.Marshal(new_file_pac)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(file_uuid, new_file_pacJSON)
	// we update the HMAC of File so we need to restore userdata too
	userdata.FileMacs[filename] = new_fileJSON_HMAC
	userJSON, err := json.Marshal(userdata)
	if err != nil {
		return nil
	}
	userJSON_encrypt := userlib.SymEnc(userdata.Uuid[:][:16], userlib.RandomBytes(16), userJSON)
	user_signature, err := userlib.DSSign(userdata.SignKey, userJSON_encrypt)
	if err != nil {
		return err
	}
	var user_pac Packet
	user_pac.Marshaled_struct = userJSON_encrypt
	user_pac.Authentication = user_signature
	user_pacJSON, err := json.Marshal(user_pac)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(userdata.Uuid, user_pacJSON)
	// go to all SharedSpaces in SharedWith, recursively see if they have shared to others.
	// update all of them with new keys and new head Content UUID
	ss_map := file.SharedWith
	err = revoke_helper(ss_map, new_symkey_source, new_signkey, new_headUUID)
	if err != nil {
		return err
	}
	return nil
}

func revoke_helper(ss_map map[string]uuid.UUID, symkey_source []byte, signkey userlib.DSSignKey, headUUID uuid.UUID) error {
	/* for i in sharedWith:
	fetch sharedSpace
	if sharedSpace.sharedWith not empty:
		revoke_helper(sharedWith, sharedWith.key <- owner name of next ss: for verify key)
	update keys and headUUID
	restore SharedSpace
	*/
	// verify_key, ok := userlib.KeystoreGet(hex.EncodeToString(hashed_ownername) + "DSVerifyKey")
	// if !ok {
	// 	err := errors.New("DSVerifyKey for hashed_ownername doesn't exist")
	// 	return err
	// }
	for recipient_name, ss_uuid := range ss_map {
		ss_pacJSON, exist := userlib.DatastoreGet(ss_uuid)
		if !exist {
			err := errors.New("shared space under uuid doesn't exist")
			return err
		}
		var ss_pac Packet
		err := json.Unmarshal(ss_pacJSON, &ss_pac)
		if err != nil {
			return err
		}
		// err = userlib.DSVerify(verify_key, ss_pac.Marshaled_struct, ss_pac.Authentication)
		// if err != nil {
		// 	return err
		// }
		// 1:17 -> :16
		caller_ss_MAC, err := userlib.HMACEval(ss_uuid[:][:16], ss_pac.Marshaled_struct)
		if err != nil {
			return err
		}
		equal := userlib.HMACEqual(caller_ss_MAC, ss_pac.Authentication)
		if !equal {
			err = errors.New("HMAC doesn't match")
			return err
		}
		if len(ss_pac.Marshaled_struct) < 16 {
			err = errors.New("cipher text length less than 16 byte")
			return err
		}
		ssJSON := userlib.SymDec(ss_uuid[:][:16], ss_pac.Marshaled_struct)
		var ss SharedSpace
		err = json.Unmarshal(ssJSON, &ss)
		if err != nil {
			return err
		}
		// recurse
		if len(ss.SharedSpaceUUIDs) != 0 {
			//hashed_ownername := userlib.Hash([]byte(next_ownername))
			err = revoke_helper(ss.SharedSpaceUUIDs, symkey_source, signkey, headUUID)
			if err != nil {
				return err
			}
		}
		// update keys and headUUID
		ss.HeadUUID = headUUID
		ss.SignKey = signkey
		hashedRecipientName := userlib.Hash([]byte(recipient_name))
		publicKey, exists := userlib.KeystoreGet(hex.EncodeToString(hashedRecipientName) + "PKEEncKey")
		if !exists {
			err = errors.New("can't find public key for recipient of ss")
			return err
		}
		encrypted_symkey, err := userlib.PKEEnc(publicKey, symkey_source)
		if err != nil {
			return err
		}
		ss.ContentSymkey = encrypted_symkey
		// store ss
		var new_ss_pac Packet
		new_ssJSON, err := json.Marshal(ss)
		if err != nil {
			return err
		}
		ssJSON_encrypt := userlib.SymEnc(ss_uuid[:][:16], userlib.RandomBytes(16), new_ssJSON)
		new_ss_pac.Marshaled_struct = ssJSON_encrypt
		new_HMAC, err := userlib.HMACEval(ss_uuid[:][:16], ssJSON_encrypt)
		if err != nil {
			return err
		}
		new_ss_pac.Authentication = new_HMAC
		new_ss_pacJSON, err := json.Marshal(new_ss_pac)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(ss_uuid, new_ss_pacJSON)
	}
	return nil
}
