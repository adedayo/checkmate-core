package gitutils

import (
	"context"
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
	repository = strings.ToLower(repository)
	//git@ is not supported, replace with https://
	if strings.HasPrefix(repository, "git@") {
		repository = strings.Replace(strings.Replace(repository, ":", "/", 1), "git@", "https://", 1)
	}

	dir, err := filepath.Abs(path.Clean(path.Join(options.BaseDir, strings.TrimSuffix(path.Base(repository), ".git"))))

	defer func() {
		if err != nil {
			log.Printf("Error: %v, %s\n", err, dir)
		}
	}()

	if err != nil {
		return "", err
	}

	if err = os.MkdirAll(dir, 0755); err != nil {
		return "", err
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

		repo, err = git.PlainCloneContext(ctx, dir, false, &git.CloneOptions{
			URL: repository,
			// Progress: os.Stdout,
			Auth:            auth,
			Depth:           options.Depth,
			InsecureSkipTLS: true, //allow self-signed on-prem servers TODO: make configurable
			NoCheckout:      options.CommitHash != "",
		})

		if err != nil {
			return "", err
		}
	} else {
		//the directory already exists, so, simply fetch if possible
		repo, err = git.PlainOpen(dir)

		if err != nil {
			return "", err
		}

		err = repo.FetchContext(ctx, &git.FetchOptions{
			Auth:            auth,
			Depth:           options.Depth,
			InsecureSkipTLS: true, //allow self-signed on-prem servers TODO: make configurable
		})

		if err != nil && err != git.NoErrAlreadyUpToDate {
			return "", err
		}

		err = nil
	}

	if options.CommitHash != "" {
		w, err := repo.Worktree()
		if err != nil {
			return "", err
		}
		err = w.Checkout(&git.CheckoutOptions{
			Hash: plumbing.NewHash(options.CommitHash),
		})
		if err != nil {
			return "", err
		}
	}
	return dir, nil
}

func directoryIsEmpty(dir string) bool {

	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	defer f.Close()

	_, err = f.Readdirnames(1)
	return err == io.EOF

}
