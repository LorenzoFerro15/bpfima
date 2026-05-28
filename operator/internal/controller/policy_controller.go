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
	"fmt"
	"maps"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	bpfimav1alpha1 "github.com/LorenzoFerro15/bpfima/api/v1alpha1"
	"github.com/LorenzoFerro15/bpfima/internal/mapsmanager"
	"github.com/cilium/ebpf"
	"github.com/go-logr/logr"
)

// PolicyReconciler reconciles a Policy object
type PolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    logr.Logger
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
	log := r.Log

	// Get the updated object
	policy := &v1alpha1.Policy{}
	err := r.Get(ctx, req.NamespacedName, policy)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("policy resource not found; ignoring since object was deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "failed to get Policy")
		return ctrl.Result{}, err
	}

	// Verify if you have to apply the policy to the current node
	ok, err := r.correctNode(ctx, policy)
	if err != nil {
		log.Error(err, "failed to determine node applicability")
		return ctrl.Result{}, err
	}
	if !ok {
		log.Info("policy does not apply to this node, skipping")
		return ctrl.Result{}, nil
	}

	// Open the maps
	mapFiles := []string{"bpfima_policy_map", "bpfima_cgroup_patterns_map", "bpfima_path_patterns_map", "bpfima_hook_config_map"}
	maps, err := mapsmanager.OpenMaps("/sys/fs/bpf/", mapFiles)
	if err != nil {
		log.Error(err, "failed to open map")
		log.Error(nil, "did you load the BPF program first?")
		return ctrl.Result{}, err
	}
	defer func() {
		for _, m := range bpfimaMaps {
			_ = m.Close()
		}
	}()

	err = r.updateMaps(maps, policy)
	if err != nil {
		log.Error(err, "failed to update BPF maps")
		return ctrl.Result{}, err
	}

	log.Info("Policy updated successfully")
	return ctrl.Result{}, nil
}

func updateMaps(bpfimaMaps map[string]*ebpf.Map, policy *bpfimav1alpha1.Policy) error {
	var err error

	err = mapsmanager.UpdatePolicy(bpfimaMaps["bpfima_policy_map"], policy.Spec.Policy, policy.Spec.Filters, policy.Spec.Actions)
	if err != nil {
		return fmt.Errorf("updating policy map: %w", err)
	}

	err = mapsmanager.UpdatePatterns(bpfimaMaps["bpfima_cgroup_patterns_map"], policy.Spec.CgroupPatterns)
	if err != nil {
		return fmt.Errorf("updating cgroup patterns map: %w", err)
	}

	err = mapsmanager.UpdatePatterns(bpfimaMaps["bpfima_path_patterns_map"], policy.Spec.PathPatterns)
	if err != nil {
		return fmt.Errorf("updating path patterns map: %w", err)
	}

	err = mapsmanager.UpdateHookConfig(bpfimaMaps["bpfima_hook_config_map"], policy.Spec.Hooks)
	if err != nil {
		return fmt.Errorf("updating hook config map: %w", err)
	}
	return nil
}

func (r *PolicyReconciler) correctNode(ctx context.Context, policy *v1alpha1.Policy) (bool, error) {
	log := logf.FromContext(ctx)

	// No selector specified: applies to all nodes
	if policy.Spec.Selector == nil {
		return true, nil
	}

	// Get the selector
	selector, err := metav1.LabelSelectorAsSelector(policy.Spec.Selector)
	if err != nil {
		return false, fmt.Errorf("failed to convert LabelSelector: %w", err)
	}

	// Get node name using the environment variable
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		log.Info("NODE_NAME not set, skipping node")
		return false, nil
	}

	// Get the node
	var node corev1.Node
	if err := r.Get(ctx, client.ObjectKey{Name: nodeName}, &node); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Node not found", "node", nodeName)
			return false, nil
		}
		return false, fmt.Errorf("failed to get node by name %w: %w", nodeName, err)
	}

	// Verify it the label in the policy matches the node one
	if !selector.Matches(labels.Set(node.Labels)) {
		return false, nil
	}

	return true, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bpfimapolitoitv1alpha1.Policy{}).
		Named("policy").
		// Call the reconciliation loop also if a change in the node's label occurs
		Watches(
			&corev1.Node{},
			// Create list of all installed policies
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
				var policyList bpfimapolitoitv1alpha1.PolicyList
				if err := r.List(ctx, &policyList); err != nil {
					return nil
				}

				// Create list of reconciliation requests
				var requests []reconcile.Request
				for _, policy := range policyList.Items {
					requests = append(requests, reconcile.Request{
						NamespacedName: types.NamespacedName{
							Name:      policy.Name,
							Namespace: policy.Namespace, // If the policy is cluster-wide it is ""
						},
					})
				}
				return requests
			}),

			// Filter on label changes
			builder.WithPredicates(predicate.Funcs{
				UpdateFunc: func(e event.UpdateEvent) bool {
					// Convert objects to nodes
					oldNode, oldOk := e.ObjectOld.(*corev1.Node)
					newNode, newOk := e.ObjectNew.(*corev1.Node)

					if !oldOk || !newOk {
						return true
					}

					// Reconcile only if the label changed for that node
					return !maps.Equal(oldNode.Labels, newNode.Labels)
				},
				CreateFunc: func(e event.CreateEvent) bool {
					// When a node is created, reconcile
					return true
				},
				DeleteFunc: func(e event.DeleteEvent) bool {
					// When a node is deleted not reconcile
					return false
				},
			}),
		).
		Complete(r)
}
