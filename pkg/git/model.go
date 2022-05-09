package gitutils

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	CHECKMATE_USER   = "checkmate"
	gitConfigManager ConfigManager
)

type Commit struct {
	Author
	Hash, Branch string
	//Commit time
	Time time.Time
	//is the default branch to scan?
	IsHead bool
}

type Author struct {
	Name, Email string
}

type GitAuth struct {
	User, Credential string
}

type GitCloneOptions struct {
	BaseDir    string // directory to clone into
	Auth       *GitAuth
	CommitHash string //if set checkout the specified commit
}

type RepositoryCloneSpec struct {
	Repository string
	ServiceID  string // the Github or Gitlab service ID
	Options    GitCloneOptions
}

const (
	GIT_SERVICE_CONFIG_FILE = "GitServiceConfig.yaml"
)

type GitServiceType int

const (
	GitHub GitServiceType = iota
	GitLab
)

type GitService struct {
	InstanceURL     string
	GraphQLEndPoint string
	APIEndPoint     string
	API_Key         string
	ID              string         //some unique ID for this service instance
	Name            string         //user-friendly name
	Type            GitServiceType `json:"_"`
}

func (svc GitService) MakeAuth() *GitAuth {
	return &GitAuth{
		User:       CHECKMATE_USER,
		Credential: svc.API_Key,
	}
}

type GitServiceConfig struct {
	GitServices map[GitServiceType]map[string]*GitService
	// manager     *configManager
}

func (gsc GitServiceConfig) IsServiceConfigured(service GitServiceType) bool {
	if services, present := gsc.GitServices[service]; present && len(services) > 0 {
		return true
	}
	return false
}

func (gsc GitServiceConfig) GetService(serviceType GitServiceType, serviceID string) (*GitService, error) {
	if services, exist := gsc.GitServices[serviceType]; exist {
		if service, found := services[serviceID]; found {
			return service, nil
		} else {
			return &GitService{}, fmt.Errorf("git service with ID %s not found", serviceID)
		}
	} else {
		return &GitService{}, fmt.Errorf("git service not configured")
	}
}

func (gsc GitServiceConfig) FindService(serviceID string) (*GitService, error) {
	for _, v := range gsc.GitServices {
		if service, found := v[serviceID]; found {
			return service, nil
		}
	}
	return &GitService{}, fmt.Errorf("git service with ID %s not found", serviceID)
}

func (gsc *GitServiceConfig) AddService(service *GitService) error {
	serviceType := service.Type
	if services, exist := gsc.GitServices[serviceType]; exist {
		services[service.ID] = service
		gsc.GitServices[serviceType] = services
	} else {
		gsc.GitServices[serviceType] = map[string]*GitService{service.ID: service}
	}
	if gitConfigManager == nil {
		return errors.New("No Git configiration manager registered")
	}
	return gitConfigManager.SaveConfig(gsc)
}

type configManager struct {
	configLocation string
}

func (cm configManager) GetConfig() (*GitServiceConfig, error) {
	conf := &GitServiceConfig{
		GitServices: make(map[GitServiceType]map[string]*GitService),
	}

	file, err := os.Open(path.Join(cm.configLocation, GIT_SERVICE_CONFIG_FILE))
	if err != nil {
		log.Printf("Error opening Git Service Configuration: %v", err)
		return conf, err
	}
	defer file.Close()

	if err := yaml.NewDecoder(file).Decode(conf); err != nil {
		log.Printf("Error opening Git Service Configuration: %v", err)
		return conf, err
	}

	return conf, nil
}

func (cm configManager) SaveConfig(conf *GitServiceConfig) error {
	file, err := os.Create(path.Join(cm.configLocation, GIT_SERVICE_CONFIG_FILE))
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := yaml.NewEncoder(file)
	defer encoder.Close()
	return encoder.Encode(conf)
}

type ConfigManager interface {
	GetConfig() (*GitServiceConfig, error)
	SaveConfig(*GitServiceConfig) error
}

//Git Service Config Manager
func NewGitConfigManager(baseDirectory string) ConfigManager {
	location := path.Join(baseDirectory, "config")

	gitConfigManager = configManager{
		configLocation: location,
	}

	//attempt to create the project location if it doesn't exist
	os.MkdirAll(location, 0755)

	return gitConfigManager
}
