/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"os"
	"os/exec"

	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/yaml"

	"github.com/LorenzoFerro15/bpfima/api/v1alpha1"
	bpfimapolitoitv1alpha1 "github.com/LorenzoFerro15/bpfima/api/v1alpha1"
)

// PolicyReconciler reconciles a Policy object
type PolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=bpfima.polito.it,resources=policies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=bpfima.polito.it,resources=policies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=bpfima.polito.it,resources=policies/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Policy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.3/pkg/reconcile
func (r *PolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Get the updated object
	policy := &v1alpha1.Policy{}
	err := r.Get(ctx, req.NamespacedName, policy)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("Policy resource not found. Ignoring since object must be deleted.")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get Policy")
		return ctrl.Result{}, err
	}

	// Convert in YAML
	yamlData, err := yaml.Marshal(policy)
	if err != nil {
		log.Error(err, "Failed to parse in YAML")
		return ctrl.Result{}, err
	}

	// Create temporary YAML file
	tmpFile, err := os.CreateTemp("", "policy-update-*.yaml")
	if err != nil {
		log.Error(err, "Failed to create tmp file")
		return ctrl.Result{}, err
	}

	// The tmp file will be removed at the end of the function
	defer os.Remove(tmpFile.Name())

	// Write the YAML file
	if _, err := tmpFile.Write(yamlData); err != nil {
		log.Error(err, "Failed to write the policy file")
		tmpFile.Close()
		return ctrl.Result{}, err
	}
	tmpFile.Close()

	// Execute policy-update
	cmd := exec.Command("/opt/bpfima/build/bpfima-tool", "policy-update", tmpFile.Name())
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(err, "Failed to update the policy", "output", string(output))
		return ctrl.Result{}, err
	}

	log.Info("Policy updated successfully", "bpfima_output", string(output))
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bpfimapolitoitv1alpha1.Policy{}).
		Named("policy").
		Complete(r)
}
