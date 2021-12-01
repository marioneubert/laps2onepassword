// This program exports Microsoft LAPS(Local Administrator Password Solution)
// managed computer/login information to an 1Password vault as replacement to
// the LAPS-UI programm
package main

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/1Password/connect-sdk-go/connect"
	"github.com/1Password/connect-sdk-go/onepassword"
	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/mattn/go-colorable"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

// LapsEntry represents LAPS information read from active directory
type LapsEntry struct {
	name        string
	dnshostname string
	password    string
	expiration  time.Time
}

// init configures logging before main
func init() {
	log.SetOutput(colorable.NewColorableStdout())
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&logrus.TextFormatter{
		ForceColors:            true,
		FullTimestamp:          true,
		DisableLevelTruncation: false,
	})
	log.SetReportCaller(false)
}

// GetAndCheckEnvironment checks all required environment variables
func GetAndCheckEnvironment() error {
	errorcount := 0
	err := godotenv.Load()
	if err != nil {
		return err
	}

	SetLoglevelFromEnvOr(log.DebugLevel)

	op_connect_host, op_connect_host_found := os.LookupEnv("OP_CONNECT_HOST")
	op_connect_token, op_connect_token_found := os.LookupEnv("OP_CONNECT_TOKEN")
	op_vault_title, op_vault_title_found := os.LookupEnv("OP_VAULT_TITLE")

	// op_connect_host
	if !op_connect_host_found {
		log.Error("GetAndCheckEnvironment: OP_CONNECT_HOST not set")
		errorcount++
	} else if op_connect_host == "" {
		log.Error("GetAndCheckEnvironment: OP_CONNECT_HOST is empty")
		errorcount++
	} else {
		log.Debug("GetAndCheckEnvironment: OP_CONNECT_HOST is ", op_connect_host)
	}

	// op_connect_token
	if !op_connect_token_found {
		log.Error("GetAndCheckEnvironment: OP_CONNECT_TOKEN not set")
		errorcount++
	} else if op_connect_token == "" {
		log.Error("GetAndCheckEnvironment: OP_CONNECT_TOKEN is empty")
		errorcount++
	} else {
		log.Debug("GetAndCheckEnvironment: OP_CONNECT_TOKEN begins with ", op_connect_token[0:9], "...")
	}

	// op_vault_title
	if !op_vault_title_found {
		log.Error("GetAndCheckEnvironment: OP_VAULT_TITLE not set")
		errorcount++
	} else if op_vault_title == "" {
		log.Error("GetAndCheckEnvironment: OP_VAULT_TITLE is empty")
		errorcount++
	} else {
		log.Debug("GetAndCheckEnvironment: OP_VAULT_TITLE is ", op_vault_title)
	}

	if errorcount == 0 {
		return nil
	}
	return errors.New("GetAndCheckEnvironment: Missing required environment variables, see previous errors")
}

// SetLoglevelFromEnvOr sets the logging level from environment.
// If environment variable is not set, set it to a default.
func SetLoglevelFromEnvOr(loglevelDefault log.Level) {
	op_loglevel, op_loglevel_found := os.LookupEnv("LOGLEVEL")
	if !op_loglevel_found {
		log.SetLevel(loglevelDefault)
		log.Info("SetLoglevelFromEnvOr: LOGLEVEL not set, defaults to ", strings.ToUpper(log.GetLevel().String()))
	} else if strings.ToUpper(op_loglevel) == "TRACE" {
		log.SetLevel(log.TraceLevel)
	} else if strings.ToUpper(op_loglevel) == "DEBUG" {
		log.SetLevel(log.DebugLevel)
	} else if strings.ToUpper(op_loglevel) == "INFO" {
		log.SetLevel(log.InfoLevel)
	} else if strings.ToUpper(op_loglevel) == "WARN" {
		log.SetLevel(log.WarnLevel)
	} else if strings.ToUpper(op_loglevel) == "ERROR" {
		log.SetLevel(log.ErrorLevel)
	} else if strings.ToUpper(op_loglevel) == "FATAL" {
		log.SetLevel(log.FatalLevel)
	} else if strings.ToUpper(op_loglevel) == "PANIC" {
		log.SetLevel(log.PanicLevel)
	} else {
		log.SetLevel(loglevelDefault)
		log.Info("SetLoglevelFromEnvOr: LOGLEVEL is not in ['TRACE','DEBUG','INFO','WARN','ERROR','FATAL','PANIC'], defaults to ", strings.ToUpper(log.GetLevel().String()))
	}
	log.Info("SetLoglevelFromEnvOr: LOGLEVEL set to ", strings.ToUpper(log.GetLevel().String()))
}

// getTimeFromFiletime is a helper function and converts
// windows FILETIME structure (64-bit value representing the number
// of 100-nanosecond intervals since January 1, 1601 (UTC)) to golang time.Time
func getTimeFromFiletime(input int64) time.Time {
	maxd := time.Duration(math.MaxInt64).Truncate(100 * time.Nanosecond)
	maxdUnits := int64(maxd / 100) // number of 100-ns units

	t := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	for input > maxdUnits {
		t = t.Add(maxd)
		input -= maxdUnits
	}
	if input != 0 {
		t = t.Add(time.Duration(input * 100))
	}
	return t
}

// GetLapsEntries connects to an active directory server
// and retrieves all computer objects configured with LAPS
func GetLapsEntries() ([]LapsEntry, error) {
	lapsentries := []LapsEntry{}

	ldapURL := os.Getenv("LDAP_URL")
	ldapCON, err := ldap.DialURL(ldapURL)
	if err != nil {
		return lapsentries, err
	}
	defer ldapCON.Close()

	err = ldapCON.Bind(os.Getenv("LDAP_AUTH_CN"), os.Getenv("LDAP_AUTH_PW"))
	if err != nil {
		return lapsentries, err
	}

	searchReq := ldap.NewSearchRequest(
		os.Getenv("LDAP_SEARCH_BASEDN"), //BaseDN
		ldap.ScopeWholeSubtree,          //Scope
		0,                               //DerefAliases
		0,                               //SizeLimit
		0,                               //TimeLimit
		false,                           //TypesOnly
		os.Getenv("LDAP_SEARCH_FILTER"), //Filter
		[]string{"name", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime", "dNSHostName"}, //Attributes
		[]ldap.Control{}, //Control
	)

	result, err := ldapCON.Search(searchReq)
	if err != nil {
		return lapsentries, err
	} else {
		log.Debug("GetLapsEntries: Got ", len(result.Entries), " entries from ldap")
		for index, entry := range result.Entries {
			log.Trace("GetLapsEntries: [", index, "] ", entry.GetAttributeValue("dNSHostName"))
			s := entry.GetAttributeValue("ms-Mcs-AdmPwdExpirationTime")
			expirationtime, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				log.Warn("GetLapsEntries: Can't convert ms-Mcs-AdmPwdExpirationTime from", s)
				expirationtime = 0
			}
			lapsentries = append(lapsentries, LapsEntry{
				name:        entry.GetAttributeValue("name"),
				dnshostname: entry.GetAttributeValue("dNSHostName"),
				password:    entry.GetAttributeValue("ms-Mcs-AdmPwd"),
				expiration:  getTimeFromFiletime(expirationtime),
			})
		}
	}
	return lapsentries, err
}

// GetOnePassEntries connects to an 1Password Connect-Server
// and retrieves all items from a special vault
func GetOnePassEntries() ([]onepassword.Item, error) {
	onepassitems := []onepassword.Item{}

	client, err := connect.NewClientFromEnvironment()
	if err != nil {
		return onepassitems, err
	}

	vaults, err := client.GetVaultsByTitle(os.Getenv("OP_VAULT_TITLE"))
	if err != nil {
		return onepassitems, err
	}
	if len(vaults) == 0 {
		return onepassitems, fmt.Errorf("Vault %s not found", os.Getenv("OP_VAULT_TITLE"))
	} else if len(vaults) > 1 {
		return onepassitems, fmt.Errorf("Vault %s found more than once", os.Getenv("OP_VAULT_TITLE"))
	}
	vault := vaults[0]
	log.Debug("GetOnePassEntries: Found vault ", vault.Name)

	onepassitems, err = client.GetItems(vault.ID)
	if err != nil {
		return onepassitems, err
	}

	log.Debug("GetOnePassEntries: Got ", len(onepassitems), " entries from onepass")

	for index, onepassitem := range onepassitems {
		log.Trace("GetOnePassEntries: [", index, "] ", onepassitem.Title)
	}

	return onepassitems, nil
}

// CompareLapsToOnepass compares all entries from LAPS with all entries
// from 1Passwort, if a item from LAPS not found it will be created
func CompareLapsToOnepass(lapsentries []LapsEntry, onepassentries []onepassword.Item) error {
	for i := range lapsentries { // use index because it's faster (no copy)
		lapsentry_found := false
		for j := range onepassentries {
			if lapsentries[i].dnshostname == onepassentries[j].Title {
				lapsentry_found = true
				break // break out of the inner loop if a match is found
			}
		}
		if lapsentry_found {
			log.Trace("CompareLapsToOnepass: Found lapsentry ", lapsentries[i].dnshostname, " in onepassentries")
			// Todo: UpdateOnPassEntryFromLapsEntry
		} else {
			log.Trace("CompareLapsToOnepass: Not found lapsentry ", lapsentries[i].dnshostname, " in onepassentries")
			err := CreateOnPassEntryFromLapsEntry(lapsentries[i])
			if err != nil {
				log.Error("CompareLapsToOnepass: Aborted due to previous error")
				return err // Errors should not occur, therefore return from here and no more api calls.
			}
		}
	}
	return nil
}

// CreateOnPassEntryFromLapsEntry creates a new item in 1Passwort
func CreateOnPassEntryFromLapsEntry(lapsEntry LapsEntry) error {
	log.Info("CreateOnPassEntryFromLapsEntry: ", lapsEntry.dnshostname)
	client, err := connect.NewClientFromEnvironment()
	if err != nil {
		log.Error("CreateOnPassEntryFromLapsEntry: ", err)
		return err
	}
	vaults, err := client.GetVaultsByTitle(os.Getenv("OP_VAULT_TITLE"))
	if err != nil {
		log.Error("CreateOnPassEntryFromLapsEntry: ", err)
		return err
	}
	if len(vaults) == 0 {
		log.Errorf("CreateOnPassEntryFromLapsEntry: Vault %s not found", os.Getenv("OP_VAULT_TITLE"))
		return err
	} else if len(vaults) > 1 {
		log.Errorf("CreateOnPassEntryFromLapsEntry: Vault %s found more than once", os.Getenv("OP_VAULT_TITLE"))
		return err
	}
	vault := vaults[0]

	opitem := onepassword.Item{
		ID:       uuid.New().String(),
		Category: "LOGIN",
		Title:    lapsEntry.dnshostname,
		Vault: onepassword.ItemVault{
			ID: vault.ID,
		},
		Fields: []*onepassword.ItemField{
			{
				ID:      uuid.New().String(),
				Type:    "STRING",
				Purpose: "USERNAME",
				Label:   "Username",
				Value:   os.Getenv("LAPS_USERNAME"),
			}, {
				ID:      uuid.New().String(),
				Type:    "STRING",
				Purpose: "PASSWORD",
				Label:   "Password",
				Value:   lapsEntry.password,
			}, {
				ID:      "notesPlain",
				Type:    "STRING",
				Purpose: "NOTES",
				Label:   "notesPlain",
				Value:   fmt.Sprintf("Created by laps2onepassword on %s", time.Now().String()),
			},
		},
	}

	opCreatedItem, err := client.CreateItem(&opitem, vault.ID)
	if err != nil {
		log.Error("CreateOnPassEntryFromLapsEntry: ", err)
		return err
	}
	log.Infof("CreateOnPassEntryFromLapsEntry: %s successfully", opCreatedItem.Title)

	return nil
}

// main start of this programm
func main() {

	log.Info("Main: Start programm")

	// Get and check environment
	// Set logging options
	err := GetAndCheckEnvironment()
	if err != nil {
		log.Panic(err)
	}

	// Get entries from ldap
	lapsentries, err := GetLapsEntries()
	if err != nil {
		log.Panic(err)
	}

	if len(lapsentries) < 1 {
		log.Panic("No entries returned from ldap")
	}

	// Get entries from onepass
	onepassentries, err := GetOnePassEntries()
	if err != nil {
		log.Panic(err)
	}
	if len(onepassentries) < 1 {
		log.Warn("No entries returned from onepass")
	}

	// CompareLapsToOnepass
	err = CompareLapsToOnepass(lapsentries, onepassentries)
	if err != nil {
		log.Error("Main: Aborted due to previous error")
		os.Exit(1)
	}
	log.Info("Main: Successfully exit")
	os.Exit(0)
}
