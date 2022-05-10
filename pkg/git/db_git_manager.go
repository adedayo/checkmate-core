package gitutils

import (
	"encoding/json"
	"errors"
	"os"
	"path"
	"strings"

	"github.com/dgraph-io/badger/v3"
)

var (
	gitConfigManagers = map[string]GitConfigManager{} // checkmateBaseDir -> ConfigManager
)

//Git Service Config Manager
func NewDBGitConfigManager(checkMateBaseDirectory string) (GitConfigManager, error) {

	//ensure the DB is singleton per base dir
	if configM, exists := gitConfigManagers[checkMateBaseDirectory]; exists {
		return configM, nil
	}

	cm := &dbGitConfigManager{
		baseDir:        checkMateBaseDirectory,
		configLocation: path.Join(checkMateBaseDirectory, "git_config_db"),
		gitConfigTable: "git_",
		initTable:      "init_",
	}

	//attempt to create the git config directory if it doesn't exist
	os.MkdirAll(cm.configLocation, 0755)

	opts := badger.DefaultOptions(cm.configLocation)

	//clean up lock on the DB if previous crash
	lockFile := path.Join(opts.Dir, "LOCK")
	_ = os.Remove(lockFile)

	db, err := badger.Open(opts)
	if err != nil {
		return cm, err
	}
	cm.db = db
	gitConfigManager = cm
	gitConfigManagers[checkMateBaseDirectory] = cm

	//import data from the YAML-based config if it exists
	importGitYAMLData(cm)

	return gitConfigManager, nil
}

func importGitYAMLData(cm *dbGitConfigManager) {

	err := cm.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(toKey(cm.initTable))
		return err
	})

	if errors.Is(err, badger.ErrKeyNotFound) {
		//create table
		cm.db.Update(func(txn *badger.Txn) error {
			return txn.Set(toKey(cm.initTable), []byte{})
		})
		yamlConfig := NewGitConfigManager(cm.baseDir)
		if config, err := yamlConfig.GetConfig(); err == nil {
			cm.SaveConfig(config)
		}
		//return global git config manager to the db one
		gitConfigManager = cm
	}
}

type dbGitConfigManager struct {
	baseDir        string ///CheckMate base directory
	configLocation string
	db             *badger.DB
	gitConfigTable string
	initTable      string
}

// GetConfig implements ConfigManager
func (cm *dbGitConfigManager) GetConfig() (*GitServiceConfig, error) {

	config := GitServiceConfig{
		GitServices: make(map[GitServiceType]map[string]*GitService),
	}
	err := cm.db.View(func(txn *badger.Txn) error {
		item, rerr := txn.Get(toKey(cm.gitConfigTable))
		if rerr != nil {
			return rerr
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &config)
		})
	})

	return &config, err
}

// SaveConfig implements ConfigManager
func (cm *dbGitConfigManager) SaveConfig(config *GitServiceConfig) error {
	return cm.db.Update(func(txn *badger.Txn) error {
		data, err := json.Marshal(config)
		if err != nil {
			return err
		}
		return txn.Set(toKey(cm.gitConfigTable), data)
	})
}

func toKey(keys ...string) []byte {
	return []byte(strings.Join(keys, ""))
}
