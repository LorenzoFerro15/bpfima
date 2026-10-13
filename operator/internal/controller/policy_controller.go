// BPFIMA custom controller to reconcile Policy configurations
package controller

import (
	"context"
	"encoding/csv"
	"fmt"
	"maps"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

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
	"github.com/LorenzoFerro15/bpfima/internal/policyselector"
	"github.com/go-logr/logr"
)

// PolicyReconciler reconciles a Policy object
type PolicyReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	Log            logr.Logger
	PolicyEndpoint string
	StatisticsPath string

	// applied reports whether a policy has been written to the maps and measured
	applied atomic.Bool
}

// Struct to save the execution times
type Stats struct {
	enterController        int64
	exitController         int64
	startMapUpdate         int64
	endMapUpdate           int64
	startPolicyMeasurement int64
	endPolicyMeasurement   int64
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *PolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log

	s := &Stats{enterController: time.Now().UnixNano()}
	defer func() {
		s.exitController = time.Now().UnixNano()
		if csvErr := s.saveStatistics(r.StatisticsPath); csvErr != nil {
			log.Error(csvErr, "failed to write statistics to file")
		}
	}()

	var selectedPolicy *bpfimav1alpha1.Policy

	// Verify if you have to apply the policy to the current node
	nodeLabel, err := r.getNodeLabel(ctx)
	if err != nil {
		log.Error(err, "failed to determine node applicability")
		return ctrl.Result{}, err
	}
	if nodeLabel == nil {
		log.Info("node not found, skipping")
		return ctrl.Result{}, nil
	}

	// Get the list of all policies
	var policyList bpfimav1alpha1.PolicyList
	if err := r.List(ctx, &policyList); err != nil {
		log.Error(nil, "failed to get the list of policies")
		return reconcile.Result{}, err
	}

	// Choose the most appropriate policy to apply
	selectedPolicy, err = policyselector.IdentifyCorrectPolicy(policyList.Items, nodeLabel)
	if err != nil {
		log.Error(err, "failed to determine policy to apply")
		return ctrl.Result{}, err
	}

	s.startMapUpdate = time.Now().UnixNano()
	s.startPolicyMeasurement = s.startMapUpdate
	endpoint := r.PolicyEndpoint
	if endpoint == "" {
		endpoint = "/sys/kernel/security/bpfima/policy_apply"
	}
	err = mapsmanager.ApplyPolicy(selectedPolicy, endpoint)
	s.endMapUpdate = time.Now().UnixNano()
	s.endPolicyMeasurement = s.endMapUpdate
	if err != nil {
		log.Error(err, "policy transaction failed; candidate was not activated")
		return ctrl.Result{}, err
	}

	r.applied.Store(true)
	log.Info("Policy updated successfully", "selected-policy", selectedPolicy.Name)

	return ctrl.Result{}, nil
}

// ReadyCheck is a readiness check that fails until a policy has been written
// to the maps and recorded in the Merkle tree, so that the node is ready only
// once the measurements follow the selected policy
func (r *PolicyReconciler) ReadyCheck(_ *http.Request) error {
	if !r.applied.Load() {
		return fmt.Errorf("no policy applied yet")
	}
	return nil
}

func (r *PolicyReconciler) getNodeLabel(ctx context.Context) (map[string]string, error) {
	log := logf.FromContext(ctx)

	// Get node name using the environment variable
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		log.Info("NODE_NAME not set, skipping node")
		return nil, nil
	}

	// Get the node
	var node corev1.Node
	if err := r.Get(ctx, client.ObjectKey{Name: nodeName}, &node); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Node not found", "node", nodeName)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get node by name %s: %w", nodeName, err)
	}

	if node.Labels == nil {
		return map[string]string{}, nil
	}
	return node.Labels, nil
}

func (s *Stats) saveStatistics(path string) error {
	if path == "" {
		path = "/tmp/controller_times.csv"
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file to store statistics: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	info, err := file.Stat()
	if err == nil && info.Size() == 0 {
		err := writer.Write([]string{"enter_controller", "exit_controller", "start_map_update", "end_map_update", "start_policy_measurement", "end_policy_measurement"})
		if err != nil {
			return fmt.Errorf("failed to write statistics to file: %w", err)
		}
	}

	row := []string{
		strconv.FormatInt(s.enterController, 10),
		strconv.FormatInt(s.exitController, 10),
		strconv.FormatInt(s.startMapUpdate, 10),
		strconv.FormatInt(s.endMapUpdate, 10),
		strconv.FormatInt(s.startPolicyMeasurement, 10),
		strconv.FormatInt(s.endPolicyMeasurement, 10),
	}

	if err := writer.Write(row); err != nil {
		return fmt.Errorf("failed to write statistics to file: %w", err)
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bpfimav1alpha1.Policy{}).
		Named("policy").
		// Call the reconciliation loop also if a change in the node's label occurs
		Watches(
			&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
				// Queue only one request with a custom name
				// The reconcile will automatically re-process all the policies
				// and choose the best one for the node
				return []reconcile.Request{
					{NamespacedName: types.NamespacedName{Name: "reconcile-all-policies"}},
				}
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
