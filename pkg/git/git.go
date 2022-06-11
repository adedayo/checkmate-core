package gitutils

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

//Clone a repository,returning the location on disk where the clone is placed
func Clone(ctx context.Context, repository string, options *GitCloneOptions) (string, error) {

	dir, err := GetCheckoutLocation(repository, options.BaseDir)

	defer func() {
		if err != nil {
			log.Printf("Error: %v, %s\n", err, dir)
		}
	}()

	if err != nil {
		return dir, err
	}

	if err = os.MkdirAll(dir, 0755); err != nil {
		return dir, err
	}

	var repo *git.Repository

	var auth *http.BasicAuth
	if options.Auth != nil {
		auth = &http.BasicAuth{
			Username: options.Auth.User,
			Password: options.Auth.Credential,
		}
	}

	if directoryIsEmpty(dir) {

		log.Printf("cloning %s", dir)
		repo, err = git.PlainCloneContext(ctx, dir, false, &git.CloneOptions{
			URL: repository,
			// Progress: os.Stdout,
			Auth:            auth,
			Depth:           options.Depth,
			InsecureSkipTLS: true, //allow self-signed on-prem servers TODO: make configurable
			NoCheckout:      options.CommitHash != "",
		})
		log.Printf("Finished cloning %s, err: %v", dir, err)
		if err != nil {
			return dir, err
		}
	} else {
		//the directory already exists, so, simply fetch if possible
		repo, err = git.PlainOpen(dir)

		if err != nil {
			return dir, err
		}

		log.Printf("Fetching %s", dir)
		err = repo.FetchContext(ctx, &git.FetchOptions{
			Auth:            auth,
			Depth:           options.Depth,
			InsecureSkipTLS: true, //allow self-signed on-prem servers TODO: make configurable
			Force:           true,
		})

		log.Printf("Finished Fetching %s, err: %v", dir, err)

		if err != nil && err != git.NoErrAlreadyUpToDate {
			return dir, err
		}

		err = nil
	}

	if options.CommitHash != "" {
		w, err := repo.Worktree()
		if err != nil {
			return dir, err
		}

		err = w.Checkout(&git.CheckoutOptions{
			Hash: plumbing.NewHash(options.CommitHash),
		})

		if err != nil {
			return dir, err
		}
	}
	return dir, nil
}

// returns the checkout location on disk for the specified git repository, given a base directory
// The pattern for base directory is baseDirectory := path.Join(pm.GetCodeBaseDir(), projectID)
func GetCheckoutLocation(repository, baseDirectory string) (string, error) {
	repository = normaliseRepository(repository)
	return filepath.Abs(path.Clean(path.Join(baseDirectory, strings.TrimSuffix(path.Base(repository), ".git"))))
}

//replaces git@ with https:// in repository URL
func normaliseRepository(repository string) string {
	//git@ is not supported, replace with https://
	if strings.HasPrefix(strings.ToLower(repository), "git@") {
		repository = strings.Replace(repository, ":", "/", 1) //replace the : in e.g. git@github.com:adedayo/checkmate.git with a /
		repository = repository[4:]                           //cut out git@
		repository = fmt.Sprintf("https://%s", repository)
	}
	return repository
}

// // returns the checkout location on disk for the specified file, given a base directory
// // The pattern for base directory is baseDirectory := path.Join(pm.GetCodeBaseDir(), projectID)
// func GetRepositoryLocation(repository, baseDirectory string) (string, error) {
// 	repository = normaliseRepository(repository)
// 	return filepath.Abs(path.Clean(path.Join(baseDirectory, path.Base(strings.Split(repository, ".git")[0]))))

// }

func directoryIsEmpty(dir string) bool {

	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	defer f.Close()

	_, err = f.Readdirnames(1)
	return err == io.EOF

}
