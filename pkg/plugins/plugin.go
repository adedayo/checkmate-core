package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/adedayo/checkmate-core/pkg/diagnostics"
)

func getFreePort() (port int, err error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return
	}

	ltcp, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return
	}
	defer ltcp.Close()
	port = ltcp.Addr().(*net.TCPAddr).Port
	return
}

func RegisterDiagnosticTransformer(transformer DiagnosticTransformer) (micro MicroService, err error) {

	port, err := getFreePort()
	if err != nil {
		return
	}
	fmt.Printf("port:%d", port)
	micro.Port = port
	mux := makeHandler(transformer)

	server := &http.Server{
		Addr:         fmt.Sprintf("localhost:%d", port),
		Handler:      mux,
		IdleTimeout:  120 * time.Second,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	}
	micro.HTTPServer = server

	return
}

func makeHandler(t DiagnosticTransformer) *http.ServeMux {
	mux := http.NewServeMux()
	dth := diagnosticTransformHandler{
		transformer: t,
	}
	mux.HandleFunc("/transform", dth.transfromDiagnostics)
	return mux
}

type diagnosticTransformHandler struct {
	transformer DiagnosticTransformer
}

func (dth diagnosticTransformHandler) transfromDiagnostics(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodPost:
		var confD ConfigDiagnostics
		err := json.NewDecoder(r.Body).Decode(&confD)
		if err != nil {
			log.Printf("Error decoding diagnostics during transform")
		}
		defer r.Body.Close()
		d := dth.transformer.Transform(confD.Config, confD.Diagnostics...)
		json.NewEncoder(w).Encode(d)

	default:
		http.Error(w, errors.New("Only POST method is supported, but got "+r.Method).Error(), http.StatusBadRequest)
		return
	}

}

type MicroService struct {
	Port       int
	HTTPServer *http.Server
	ch         chan os.Signal
}

func (m MicroService) ShutDown() {
	m.HTTPServer.Shutdown(context.Background())
}

func (m *MicroService) Start() {
	go func() {
		m.HTTPServer.ListenAndServe()
	}()

	m.ch = make(chan os.Signal)
	signal.Notify(m.ch, os.Interrupt, os.Kill)
	s := <-m.ch
	log.Printf("Shutting Microservice down with signal %v", s)
}

type pluginRunner struct {
	path         string
	transformURL string
}

// Transform implements DiagnosticTransformer
func (p pluginRunner) Transform(config *Config, diags ...*diagnostics.SecurityDiagnostic) []*diagnostics.SecurityDiagnostic {
	data, err := json.Marshal(ConfigDiagnostics{
		Config:      config,
		Diagnostics: diags,
	})
	if err != nil {
		log.Printf("Error marshalling diagnostics: %v", err)
		return diags //noop
	}

	resp, err := http.Post(p.transformURL, "application/json", bytes.NewBuffer(data))

	if err != nil {
		log.Printf("Error invoking microservice transform endpoint: %v", err)
		return diags //noop
	}

	defer resp.Body.Close()
	out := []*diagnostics.SecurityDiagnostic{}

	err = json.NewDecoder(resp.Body).Decode(&out)

	if err != nil {
		log.Printf("Error decoding diagnostics response: %v", err)
		return diags //noop
	}

	return out
}

// creates and runs a new diagnostic transformer plugin
func NewDiagnosticTransformerPlugin(path string) (DiagnosticTransformer, error) {
	runner := pluginRunner{
		path: path,
	}

	cmd := exec.Command(path)

	stdout := bytes.Buffer{}
	cmd.Stdout = &stdout

	err := cmd.Start()
	if err != nil {
		return runner, err
	}

	time.Sleep(3 * time.Second) //sleep to allow output from plugin

	output := stdout.String()
	p := strings.Split(output, ":")
	if len(p) != 2 {
		return runner, fmt.Errorf("Expecting output 'port:<number>' but got '%s'", output)
	}

	port, err := strconv.Atoi(strings.TrimSpace(p[1]))
	if err != nil {
		return runner, fmt.Errorf("Expecting port as a number but got '%s'", p[1])
	}
	runner.transformURL = fmt.Sprintf("http://localhost:%d/transform", port)
	return runner, nil
}
