// This program exports Microsoft LAPS(Local Administrator Password Solution)
// managed computer/login information to an 1Password vault as replacement to
// the LAPS-UI programm
package main

import (
	"errors"
	"flag"
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
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Commandline flags
var flag_loglevel string
var flag_logfile string

// LapsEntry represents LAPS information read from active directory
type LapsEntry struct {
	name        string
	dnshostname string
	password    string
	expiration  time.Time
}

// init configures logging before main
func init() {

	flag.StringVar(&flag_loglevel, "loglevel", "info", "set loglevel [trace,debug,info,warn,error,fatal,panic]")
	flag.StringVar(&flag_logfile, "logfile", "", "write log to specified file (disables stdout)")
	flag.Parse()
	InitLogger()
}

func InitLogger() {
	// Level
	_loglevel := strings.ToLower(flag_loglevel)
	switch {
	case _loglevel == "trace":
		log.SetLevel(log.TraceLevel)
	case _loglevel == "debug":
		log.SetLevel(log.DebugLevel)
	case _loglevel == "info":
		log.SetLevel(log.InfoLevel)
	case _loglevel == "warn":
		log.SetLevel(log.WarnLevel)
	case _loglevel == "warning":
		log.SetLevel(log.WarnLevel)
	case _loglevel == "error":
		log.SetLevel(log.ErrorLevel)
	case _loglevel == "fatal":
		log.SetLevel(log.FatalLevel)
	case _loglevel == "panic":
		log.SetLevel(log.PanicLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}

	if flag_logfile == "" {
		log.SetFormatter(&log.TextFormatter{
			ForceColors:     true, // Seems like automatic color detection doesn't work on windows terminals
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
		})
		log.SetOutput(colorable.NewColorableStdout())
	} else {
		log.SetFormatter(&log.TextFormatter{
			ForceColors:     false, // Seems like automatic color detection doesn't work on windows terminals
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
		})
		log.SetOutput(&lumberjack.Logger{
			Filename:   flag_logfile,
			MaxSize:    50, // megabytes
			MaxBackups: 3,
			MaxAge:     90,    //days
			Compress:   false, // disabled by default
		})
	}
	log.Debug("InitLogger: Loglevel set to ", strings.ToLower(log.GetLevel().String()))
}

// GetAndCheckEnvironment checks all required environment variables
func GetAndCheckEnvironment() error {
	errorcount := 0
	err := godotenv.Load()
	if err != nil {
		return err
	}

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
	opEmptyItems := []onepassword.Item{}
	opListItems := []onepassword.Item{}
	opFullItems := []onepassword.Item{}

	client, err := connect.NewClientFromEnvironment()
	if err != nil {
		return opEmptyItems, err
	}

	vaults, err := client.GetVaultsByTitle(os.Getenv("OP_VAULT_TITLE"))
	if err != nil {
		return opEmptyItems, err
	}
	if len(vaults) == 0 {
		return opEmptyItems, fmt.Errorf("vault %s not found", os.Getenv("OP_VAULT_TITLE"))
	} else if len(vaults) > 1 {
		return opEmptyItems, fmt.Errorf("fault %s found more than once", os.Getenv("OP_VAULT_TITLE"))
	}
	vault := vaults[0]
	log.Debug("GetOnePassEntries: Found vault ", vault.Name)

	opListItems, err = client.GetItems(vault.ID)
	if err != nil {
		return opEmptyItems, err
	}

	log.Debug("GetOnePassEntries: Got ", len(opListItems), " list entries from onepass")

	for index, opListItem := range opListItems {
		opFullItem, err := client.GetItem(opListItem.ID, opListItem.Vault.ID)
		if err != nil {
			return opEmptyItems, err
		}
		log.Trace("GetOnePassEntries: [", index, "] ", opFullItem.Title)
		opFullItems = append(opFullItems, *opFullItem)
	}

	return opFullItems, nil
}

// CompareLapsToOnepass compares all entries from LAPS with all entries
// from 1Passwort, if a item from LAPS not found it will be created
func CompareLapsToOnepass(lapsentries []LapsEntry, onepassentries []onepassword.Item) error {
	_created_total := 0
	_updated_total := 0
	var cur_laps_idx = 0
	var cur_op_idx = 0
	for cur_laps_idx = range lapsentries { // use index because it's faster (no copy)
		lapsentry_found := false
		cur_op_idx = 0
		for cur_op_idx = range onepassentries {
			if lapsentries[cur_laps_idx].dnshostname == onepassentries[cur_op_idx].Title {
				lapsentry_found = true
				break // break out of the inner loop if a match is found
			}
		}
		if lapsentry_found {
			log.Trace("CompareLapsToOnepass: Found lapsentry ", lapsentries[cur_laps_idx].dnshostname, " in onepassentries")
			if lapsentries[cur_laps_idx].password != onepassentries[cur_op_idx].GetValue("password") {
				log.Info("CompareLapsToOnepass: Update required ", lapsentries[cur_laps_idx].dnshostname)
				err := UpdateOnPassEntry(onepassentries[cur_op_idx], lapsentries[cur_laps_idx])
				if err != nil {
					log.Error("CompareLapsToOnepass: Aborted due to previous error")
					return err // Errors should not occur, therefore return from here and no more api calls.
				}
				_updated_total++
			}
		} else {
			log.Trace("CompareLapsToOnepass: Not found lapsentry ", lapsentries[cur_laps_idx].dnshostname, " in onepassentries")
			err := CreateOnPassEntryFromLapsEntry(lapsentries[cur_laps_idx])
			if err != nil {
				log.Error("CompareLapsToOnepass: Aborted due to previous error")
				return err // Errors should not occur, therefore return from here and no more api calls.
			}
			_created_total++
		}
	}
	log.Infof("CompareLapsToOnepass: Total created=%d updated=%d", _created_total, _updated_total)
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

func UpdateOnPassEntry(onepassentry onepassword.Item, lapsEntry LapsEntry) error {
	log.Info("UpdateOnPassEntry: ", lapsEntry.dnshostname)
	client, err := connect.NewClientFromEnvironment()
	if err != nil {
		log.Error("UpdateOnPassEntry: ", err)
		return err
	}

	if onepassentry.Fields[1].Purpose == "PASSWORD" {
		onepassentry.Fields[1].Value = lapsEntry.password
	} else {
		log.Panicf("UpdateOnPassEntry: Fields[1] purpose is not PASSWORD on %s", onepassentry.Title)
	}

	if onepassentry.Fields[2].Purpose == "NOTES" {
		onepassentry.Fields[2].Value = fmt.Sprintf("Updated by laps2onepassword on %s", time.Now().String())
	} else {
		log.Panicf("UpdateOnPassEntry: Fields[2] purpose is not NOTES on %s", onepassentry.Title)
	}

	client.UpdateItem(&onepassentry, onepassentry.Vault.ID)
	if err != nil {
		log.Error("UpdateOnPassEntry: ", err)
		return err
	}

	log.Infof("UpdateOnPassEntry: %s successfully", onepassentry.Title)
	return nil

}

// main start of this programm
func main() {

	log.Debug("Main: Start programm")

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
	log.Debug("Main: Successfully exit")
	os.Exit(0)
}
