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

	"k8s.io/apimachinery/pkg/api/errors"

	"github.com/LorenzoFerro15/bpfima/api/v1alpha1"
	bpfimapolitoitv1alpha1 "github.com/LorenzoFerro15/bpfima/api/v1alpha1"
	"github.com/LorenzoFerro15/bpfima/internal/mapsmanager"
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

	// Open the maps
	mapFiles := []string{"bpfima_policy_map", "bpfima_cgroup_patterns_map", "bpfima_path_patterns_map", "bpfima_hook_config_map"}
	maps, err := mapsmanager.OpenMaps("/sys/fs/bpf/", mapFiles)
	if err != nil {
		log.Error(err, "Failed to open map")
		log.Error(nil, "Did you load the BPF program first?")
		return ctrl.Result{}, err
	}
	defer func() {
		for _, m := range maps {
			m.Close()
		}
	}()

	// Update the maps
	err = mapsmanager.UpdatePolicy(maps["bpfima_policy_map"], policy.Spec.Policy, policy.Spec.Filters, policy.Spec.Actions)
	if err != nil {
		log.Error(err, "Failed to update policy map")
		return ctrl.Result{}, err
	}

	err = mapsmanager.UpdatePatterns(maps["bpfima_cgroup_patterns_map"], policy.Spec.CgroupPatterns)
	if err != nil {
		log.Error(err, "Failed to update cgroup patterns")
		return ctrl.Result{}, err
	}

	err = mapsmanager.UpdatePatterns(maps["bpfima_path_patterns_map"], policy.Spec.PathPatterns)
	if err != nil {
		log.Error(err, "Failed to update cgroup patterns")
		return ctrl.Result{}, err
	}

	err = mapsmanager.UpdateHookConfig(maps["bpfima_hook_config_map"], policy.Spec.Hooks)
	if err != nil {
		log.Error(err, "Failed to update path patterns")
		return ctrl.Result{}, err
	}

	log.Info("Policy updated successfully")
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bpfimapolitoitv1alpha1.Policy{}).
		Named("policy").
		Complete(r)
}
