package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	"strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	var frank *client.User
	var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("Custom Test", func() {

		Specify("Testing User", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing bob again.")
			charles, err = client.InitUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initialize user Bob: should be case sensitive.")
			charles, err = client.InitUser("Bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob.")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Empty username")
			charles, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Empty password (allowed)")
			charles, err = client.InitUser("charles", "")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user with incorrect password")
			charles, err = client.GetUser("bob", "")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initialize a user that's large")
			charles, err = client.InitUser(strings.Repeat("charles", 1000), strings.Repeat("bananaslug", 1200))
			Expect(err).To(BeNil())

		})

		Specify("Test on File Operation", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles creates file with empty filename with empty content")
			err = charles.StoreFile("", []byte(""))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles loads file with empty filename and get empty content")
			data, err := charles.LoadFile("")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("")))

			userlib.DebugMsg("Alice creates file called %s with empty content", aliceFile)
			err = alice.StoreFile(aliceFile, []byte(""))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creates file called %s with %s", aliceFile, contentOne)
			err = bob.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice loads file %s and get empty content", aliceFile)
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("")))

			userlib.DebugMsg("Bob loads file %s and get %s", aliceFile, contentOne)
			data, err = bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice appends file %s with %s", aliceFile, contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice loads file %s and get %s", aliceFile, contentTwo)
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Bob loads file %s and get %s", aliceFile, contentOne)
			data, err = bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice overwrites file %s with %s", aliceFile, contentThree)
			err = alice.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice loads file %s and get %s", aliceFile, contentThree)
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))

			userlib.DebugMsg("Bob loads non-exist file %s and should fail", bobFile)
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("Test Append Bandwidth", func() {
			userlib.DebugMsg("Initialize user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates file called %s with empty content", aliceFile)
			err = alice.StoreFile(aliceFile, []byte(""))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice appends file %s with %s", aliceFile, contentTwo)
			bw1 := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			bw2 := userlib.DatastoreGetBandwidth()
			diff1 := bw2 - bw1
			userlib.DebugMsg("Append1 takes bandwidth: %d", diff1)

			bw3 := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			bw4 := userlib.DatastoreGetBandwidth()
			diff := bw4 - bw3
			userlib.DebugMsg("Alice appends file %s with %s for 10 times", aliceFile, contentTwo)
			for i := 0; i < 10; i++ {
				bw3 := userlib.DatastoreGetBandwidth()
				err = alice.AppendToFile(aliceFile, []byte(contentTwo))
				Expect(err).To(BeNil())
				bw4 := userlib.DatastoreGetBandwidth()
				diff2 := bw4 - bw3
				userlib.DebugMsg("Check bandwidth between appends with same length")
				Expect(diff2 - diff).To(BeNumerically("~", 0, 10))
				diff = diff2
			}

		})

		Specify("Test Sharing and Revocation", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates file with empty filename with empty content")
			err = alice.StoreFile("", []byte(""))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creates file with empty filename with empty content")
			err = bob.StoreFile("", []byte(""))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice shares the file with Bob")
			invite, err := alice.CreateInvitation("", "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts invite with empty filename, should fail")
			err = bob.AcceptInvitation("alice", invite, "")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles tries to accept invite, should fail")
			err = charles.AcceptInvitation("alice", invite, "")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob accepts invite under filename %s", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice shares the file with Charles")
			invite, err = alice.CreateInvitation("", "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice immediately revoke the invite")
			err = alice.RevokeAccess("", "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles tries to accept the revoked invite, should fail")
			err = charles.AcceptInvitation("alice", invite, "")
			Expect(err).ToNot(BeNil())

		})

		Specify("Test Sharing and Revocation + File Operation", func() {
			userlib.DebugMsg("Initializing users.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			frank, err = client.InitUser("frank", defaultPassword)
			Expect(err).To(BeNil())

			grace, err = client.InitUser("grace", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice on laptop.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates file with empty filename with empty content")
			err = alice.StoreFile("", []byte(""))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice shares the file under wrong filename, should fail")
			_, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice shares the file with Bob")
			invite, err := alice.CreateInvitation("", "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts invite under filename %s", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice shares the file with Charles")
			invite, err = alice.CreateInvitation("", "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepts the invite under filename %s", charlesFile)
			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Create share tree")
			invite, err = bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())
			err = doris.AcceptInvitation("bob", invite, "")
			Expect(err).To(BeNil())
			invite, err = charles.CreateInvitation(charlesFile, "eve")
			Expect(err).To(BeNil())
			err = eve.AcceptInvitation("charles", invite, "")
			Expect(err).To(BeNil())
			invite, err = charles.CreateInvitation(charlesFile, "frank")
			Expect(err).To(BeNil())
			err = frank.AcceptInvitation("charles", invite, "")
			Expect(err).To(BeNil())
			invite, err = eve.CreateInvitation("", "grace")
			Expect(err).To(BeNil())
			err = grace.AcceptInvitation("eve", invite, "")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Eve appends to file with %s", contentTwo)
			err = eve.AppendToFile("", []byte(contentTwo))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Alice (laptop) loads the file, should see %s", contentTwo)
			data, err := aliceLaptop.LoadFile("")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
			userlib.DebugMsg("Frank overwrites the file with %s", contentThree)
			err = frank.StoreFile("", []byte(contentThree))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Doris loads the file, should see %s", contentThree)
			data, err = doris.LoadFile("")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))
			userlib.DebugMsg("Bob appends to file twice, with %s", contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Charles loads the file, should see %s", contentThree+contentTwo+contentTwo)
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree + contentTwo + contentTwo)))

			userlib.DebugMsg("Alice (laptop) revokes Bob")
			err = aliceLaptop.RevokeAccess("", "bob")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Check that doris should lost access, too")
			_, err = doris.LoadFile("")
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Bob tries to append to file after revocation")
			err = bob.AppendToFile(bobFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Check that eve, frank, grace should still be able to access file")
			_, err = eve.LoadFile("")
			Expect(err).To(BeNil())
			_, err = frank.LoadFile("")
			Expect(err).To(BeNil())
			_, err = grace.LoadFile("")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Check append bandwidth after file sharing")
			bw3 := userlib.DatastoreGetBandwidth()
			err = grace.AppendToFile("", []byte(contentTwo))
			Expect(err).To(BeNil())
			bw4 := userlib.DatastoreGetBandwidth()
			diff := bw4 - bw3
			userlib.DebugMsg("Grace appends to file with %s for 10 times", contentTwo)
			for i := 0; i < 10; i++ {
				bw3 := userlib.DatastoreGetBandwidth()
				err = grace.AppendToFile("", []byte(contentTwo))
				Expect(err).To(BeNil())
				bw4 := userlib.DatastoreGetBandwidth()
				diff2 := bw4 - bw3
				userlib.DebugMsg("Check bandwidth between appends with same length")
				Expect(diff2 - diff).To(BeNumerically("~", 0, 10))
				diff = diff2
			}

			// userlib.DebugMsg("Doris tries to overwrite file after revocation")  <- undefined
			// err = doris.StoreFile("")

		})

		Specify("Malicious manipulation", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates file called %s with %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creates file called %s with %s", bobFile, contentOne)
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice shares the file with Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts the file under empty filename")
			err = bob.AcceptInvitation("alice", invite, "")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Corrupting data")
			datastoreMap := userlib.DatastoreGetMap()
			for uuid, bytes := range datastoreMap {
				bytes[0] += 1
				userlib.DatastoreSet(uuid, bytes)
			}

			userlib.DebugMsg("Alice tries to store to the file, should fail")
			err = alice.StoreFile(aliceFile, []byte(""))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob tries to share the file to Charles, should fail")
			_, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).ToNot(BeNil())

		})

		Specify("swapping value in datastore", func() {

			userlib.DebugMsg("initialize user alice and bob")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Swapping data in datastore")
			datastoreMap := userlib.DatastoreGetMap()

			entries := make(map[string][]byte)
			i := 0
			for _, value := range datastoreMap {
				if i == 0 {
					entries["0"] = value
				} else {
					entries["1"] = value
				}
			}
			// Update the original map
			j := 0
			for key := range datastoreMap {
				if j == 0 {
					userlib.DatastoreSet(key, entries["1"])
				} else {
					userlib.DatastoreSet(key, entries["1"])
				}

			}

			userlib.DebugMsg("try to access user, should fail")
			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("try to create file, should fail")
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

		})
	})
})
