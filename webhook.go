package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	"k8s.io/api/admission/v1beta1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/kubernetes/pkg/apis/core/v1"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()

	// (https://github.com/kubernetes/kubernetes/issues/57982)
	defaulter = runtime.ObjectDefaulter(runtimeScheme)
)

var ignoredNamespaces = []string {
	metav1.NamespaceSystem,
	metav1.NamespacePublic,
}

const (
	admissionWebhookAnnotationInjectKey = "sidecar-injector-webhook.morven.me/inject"
	admissionWebhookAnnotationStatusKey = "sidecar-injector-webhook.morven.me/status"
	standardTestGridLoc = "opt/testgrid/"
)

type WebhookServer struct {
	sidecarConfig    *Config
	logPathConfig    *logConfigs
	server           *http.Server
}

// Webhook Server parameters
type WhSvrParameters struct {
	port int                 // webhook server port
	certFile string          // path to the x509 certificate for https
	keyFile string           // path to the x509 private key matching `CertFile`
	sidecarCfgFile string    // path to sidecar injector configuration file
	logPathConfigFile string
}

type logConfig struct {
	Name string  `yaml:"name"`
	Path string  `yaml:"path"`
}

type logConfigs struct {
	Loglocs []logConfig   `yaml:"loglocs"`
	Onlyes string      `yaml:"onlyes"`
}

type Config struct {
	Containers  []corev1.Container   `yaml:"containers"`
	Volumes     []corev1.Volume      `yaml:"volumes"`
	VolumeMounts []corev1.VolumeMount `yaml:"volumeMount"`
	Env []corev1.EnvVar     `yaml:"env"`
	InitContainers []corev1.Container `yaml:"initcontainers"`
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func init() {
	_ = corev1.AddToScheme(runtimeScheme)
	_ = admissionregistrationv1beta1.AddToScheme(runtimeScheme)
	// defaulting with webhooks:
	// https://github.com/kubernetes/kubernetes/issues/57982
	_ = v1.AddToScheme(runtimeScheme)
}

// (https://github.com/kubernetes/kubernetes/issues/57982)
func applyDefaultsWorkaround(containers []corev1.Container, volumes []corev1.Volume) {
	defaulter.Default(&corev1.Pod {
		Spec: corev1.PodSpec {
			Containers:     containers,
			Volumes:        volumes,
		},
	})
}

func loadLogPaths(logPathconfigFile string) (*logConfigs, error){
	yamlFile, err := ioutil.ReadFile(logPathconfigFile)
	glog.Infof(strconv.Itoa(len(yamlFile)))
	if err != nil {
		return nil, err
	}

	var logConfs logConfigs
	if err := yaml.Unmarshal(yamlFile, &logConfs); err != nil{
		return nil,err
	}

	return &logConfs, nil
}

func loadConfig(configFile string) (*Config, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	glog.Infof("New configuration: sha256sum %x", sha256.Sum256(data))

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func checkLogpathConfs(depname string, logConfs *logConfigs) bool{
	for _, logLoc := range  logConfs.Loglocs {
		if strings.Contains(logLoc.Name,depname) {
			glog.Infof("required in deployment and container pair ", logLoc.Name)
			return true
		}
	}
	return false
}
// Check whether the target resoured need to be mutated
func mutationRequired(ignoredList []string, metadata *metav1.ObjectMeta, depname string, logConfs *logConfigs) bool {
	// skip special kubernete system namespaces
	for _, namespace := range ignoredList {
		if metadata.Namespace == namespace {
			glog.Infof("Skip mutation for %v for it' in special namespace:%v", metadata.Name, metadata.Namespace)
			return false
		}
	}

	annotations := metadata.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	status := annotations[admissionWebhookAnnotationStatusKey]

	// determine whether to perform mutation based on annotation for the target resource
	var required bool
	if strings.ToLower(status) == "injected" {
		required = false;
	} else {
		required = checkLogpathConfs(depname, logConfs)
	}

	glog.Infof("Mutation policy for %v/%v: status: %q required:%v", metadata.Namespace, metadata.Name, status,
		required)
	return required
}

func addContainer(target, added []corev1.Container, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Container{add}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation {
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func addVolumeMount(target, added []corev1.VolumeMount, basePath string) (patch []patchOperation){
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.VolumeMount{add}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation {
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func addEnvVar(target, added []corev1.EnvVar, basePath string) (patch []patchOperation){
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.EnvVar{add}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation {
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func addVolume(target, added []corev1.Volume, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Volume{add}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation {
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}


func addInitContainer(target, added []corev1.Container, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Container{add}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation {
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func updateAnnotation(target map[string]string, added map[string]string) (patch []patchOperation) {
	for key, value := range added {
		if target == nil || target[key] == "" {
			target = map[string]string{}
			patch = append(patch, patchOperation {
				Op:   "add",
				Path: "/metadata/annotations",
				Value: map[string]string{
					key: value,
				},
			})
		} else {
			patch = append(patch, patchOperation {
				Op:    "replace",
				Path:  "/metadata/annotations/" + key,
				Value: value,
			})
		}
	}
	return patch
}

func findLogPath(key string, logConfs *logConfigs ) (path string) {
	for _, logLoc := range  logConfs.Loglocs {
		glog.Infof(logLoc.Name, key)
		if logLoc.Name == key {
			return logLoc.Path
		}
	}
	glog.Info("No path found for ",key,"using default")
	return "/opt/testgrid/logs"
}

// create mutation patch for resoures
func createPatch(pod *corev1.Pod, sidecarConfig *Config, annotations map[string]string, logConfs *logConfigs ) ([]byte, error) {

	var patch []patchOperation

	var containerList = pod.Spec.Containers;

	var podRandomName = pod.GenerateName
	var podHash = "-" + pod.Labels["pod-template-hash"] + "-"
	var depName = strings.Replace(podRandomName, podHash, "",1)



	// Adding the environment variables to each container
	for index, container := range containerList {
		Envpath := "/spec/containers/"+strconv.Itoa(index)+"/env"
		patch = append(patch, addEnvVar(container.Env, sidecarConfig.Env, Envpath)...)
	}

	// Adding the init containers
	patch = append(patch, addInitContainer(pod.Spec.InitContainers,
		sidecarConfig.InitContainers, "/spec/initContainers")...)

	// Adding the fixed volumes to each container
	patch = append(patch, addVolume(pod.Spec.Volumes, sidecarConfig.Volumes, "/spec/volumes")...)

	// Adding annotations
	patch = append(patch, updateAnnotation(pod.Annotations, annotations)...)


	// Adding volume Mounts to containers
	var sidecarInjectVolMounts = []corev1.VolumeMount{}
	var volumes = []corev1.Volume{}

	for index, container := range containerList {

		var containerInjectVolMounts = []corev1.VolumeMount{}
		var logPathKey = depName + "-" + container.Name
		var logPath = findLogPath(logPathKey, logConfs)
		var injectedVolMount = corev1.VolumeMount{Name:"testgrid-"+strconv.Itoa(index) ,
			MountPath: logPath}
		var sidecarInjectedVolMount = corev1.VolumeMount{Name:"testgrid-"+strconv.Itoa(index) ,
			MountPath:standardTestGridLoc+container.Name}

		var logVolSource = corev1.VolumeSource{EmptyDir: nil}
		var logVolume = corev1.Volume{Name: "testgrid-"+strconv.Itoa(index), VolumeSource: logVolSource}

		sidecarInjectVolMounts = append(sidecarInjectVolMounts, sidecarInjectedVolMount)
		containerInjectVolMounts = append(containerInjectVolMounts, injectedVolMount)

		volumes = append(volumes, logVolume)

		volMountpath := "/spec/containers/"+strconv.Itoa(index)+"/volumeMounts"
		patch = append(patch, addVolumeMount(container.VolumeMounts, containerInjectVolMounts, volMountpath)...)

	}

	sidecarInjectVolMounts = append(sidecarInjectVolMounts, corev1.VolumeMount{Name:"shared-plugins-logstash" ,
		MountPath:"/usr/share/logstash/plugins/"})
	sidecarInjectVolMounts = append(sidecarInjectVolMounts, corev1.VolumeMount{Name:"logstash-yaml" ,
		MountPath:"/usr/share/logstash/config/logstash.yml", SubPath: "logstash.yml", ReadOnly:false })
	sidecarInjectVolMounts = append(sidecarInjectVolMounts, corev1.VolumeMount{Name:"logstash-conf" ,
		MountPath:"/usr/share/logstash/pipeline/logstash.conf", SubPath: "logstash.conf"})
	sidecarInjectVolMounts = append(sidecarInjectVolMounts, corev1.VolumeMount{Name:"sincedb-mount",
		MountPath:standardTestGridLoc+"sincedb", SubPath:"sincedb", ReadOnly:false})

	// Add the sidecar
	var sideCarList = []corev1.Container{};
	var sideCar = corev1.Container{
		Name:         "logstash-sidecar",
		Image:        "docker.elastic.co/logstash/logstash:7.2.0",
		Env:          sidecarConfig.Env,
		VolumeMounts: sidecarInjectVolMounts,
	}
	sideCarList = append(sideCarList, sideCar)
	patch = append(patch, addContainer(pod.Spec.Containers, sideCarList, "/spec/containers")...)
	// Configuring the sidecar with volume Mounts

	// Adding volumes to container
	patch = append(patch, addVolume(pod.Spec.Volumes, volumes, "/spec/volumes")...)

	return json.Marshal(patch)
}

// main mutation process
func (whsvr *WebhookServer) mutate(ar *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	glog.Info(whsvr.logPathConfig)
	req := ar.Request
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		glog.Errorf("Could not unmarshal raw object: %v", err)
		return &v1beta1.AdmissionResponse {
			Result: &metav1.Status {
				Message: err.Error(),
			},
		}
	}

	glog.Infof("AdmissionReview for Kind=%v, Namespace=%v Name=%v (%v) UID=%v patchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, pod.Name, req.UID, req.Operation, req.UserInfo)

	// determine whether to perform mutation
	var podRandomName = pod.GenerateName
	var podHash = "-" + pod.Labels["pod-template-hash"] + "-"
	var depName = strings.Replace(podRandomName, podHash, "",1)
	if !mutationRequired(ignoredNamespaces, &pod.ObjectMeta, depName,whsvr.logPathConfig) {
		glog.Infof("Skipping mutation for %s/%s due to policy check", pod.Namespace, pod.Name)
		return &v1beta1.AdmissionResponse {
			Allowed: true,
		}
	}

	// Workaround: https://github.com/kubernetes/kubernetes/issues/57982
	applyDefaultsWorkaround(whsvr.sidecarConfig.Containers, whsvr.sidecarConfig.Volumes)
	annotations := map[string]string{admissionWebhookAnnotationStatusKey: "injected"}
	patchBytes, err := createPatch(&pod, whsvr.sidecarConfig, annotations, whsvr.logPathConfig)
	if err != nil {
		return &v1beta1.AdmissionResponse {
			Result: &metav1.Status {
				Message: err.Error(),
			},
		}
	}

	glog.Infof("AdmissionResponse: patch=%v\n", string(patchBytes))
	return &v1beta1.AdmissionResponse {
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

// Serve method for webhook server
func (whsvr *WebhookServer) serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		glog.Error("empty body")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		glog.Errorf("Content-Type=%s, expect application/json", contentType)
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var admissionResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		glog.Errorf("Can't decode body: %v", err)
		admissionResponse = &v1beta1.AdmissionResponse {
			Result: &metav1.Status {
				Message: err.Error(),
			},
		}
	} else {
		admissionResponse = whsvr.mutate(&ar)
	}

	admissionReview := v1beta1.AdmissionReview{}
	if admissionResponse != nil {
		admissionReview.Response = admissionResponse
		if ar.Request != nil {
			admissionReview.Response.UID = ar.Request.UID
		}
	}

	resp, err := json.Marshal(admissionReview)
	if err != nil {
		glog.Errorf("Can't encode response: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}
	glog.Infof("Ready to write reponse ...")
	if _, err := w.Write(resp); err != nil {
		glog.Errorf("Can't write response: %v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}
