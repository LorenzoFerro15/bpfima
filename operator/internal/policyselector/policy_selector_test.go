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

package policyselector

import (
	"testing"
	"time"

	bpfimav1alpha1 "github.com/LorenzoFerro15/bpfima/api/v1alpha1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIdentifyCorrectPolicy(t *testing.T) {
	oldTS := metav1.NewTime(time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC))
	newTS := metav1.NewTime(time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC))

	tests := []struct {
		name         string
		nodeLabel    map[string]string
		policies     []bpfimav1alpha1.Policy
		expectPolicy *bpfimav1alpha1.Policy
	}{
		// Verify that the default policy is chosen if the only one present
		{
			name:         "default",
			nodeLabel:    nil,
			policies:     []bpfimav1alpha1.Policy{},
			expectPolicy: &defaultPolicy,
		},

		// Verify that the labelled policy is selected if matching the node label even if generic is present
		{
			name:      "Labelled policy matching node label",
			nodeLabel: map[string]string{"color": "green"},
			policies: []bpfimav1alpha1.Policy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "green"},
					Spec: bpfimav1alpha1.PolicySpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"color": "green",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "blue"},
					Spec: bpfimav1alpha1.PolicySpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"color": "blue",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "generic"},
				},
			},
			expectPolicy: &bpfimav1alpha1.Policy{
				ObjectMeta: metav1.ObjectMeta{Name: "green"},
				Spec: bpfimav1alpha1.PolicySpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"color": "green",
						},
					},
				},
			},
		},

		// Verify that the default policy is selected if the labelled policy does not match the node label
		{
			name:      "Labelled policy not matching node label",
			nodeLabel: nil,
			policies: []bpfimav1alpha1.Policy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "green"},
					Spec: bpfimav1alpha1.PolicySpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"color": "green",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "blue"},
					Spec: bpfimav1alpha1.PolicySpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"color": "blue",
							},
						},
					},
				},
			},
			expectPolicy: &defaultPolicy,
		},

		// As above, but a generic policy is present
		{
			name:      "Labelled policy not matching node label but generic present",
			nodeLabel: map[string]string{"color": "red"},
			policies: []bpfimav1alpha1.Policy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "green"},
					Spec: bpfimav1alpha1.PolicySpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"color": "green",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "blue"},
					Spec: bpfimav1alpha1.PolicySpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"color": "blue",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "generic"},
				},
			},
			expectPolicy: &bpfimav1alpha1.Policy{
				ObjectMeta: metav1.ObjectMeta{Name: "generic"},
			},
		},

		// Verify that between two generic policies the most recent is chosen
		{
			name:      "Two generic policies present",
			nodeLabel: map[string]string{"color": "red"},
			policies: []bpfimav1alpha1.Policy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "green"},
					Spec: bpfimav1alpha1.PolicySpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"color": "green",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "generic-old",
						CreationTimestamp: oldTS,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "generic-new",
						CreationTimestamp: newTS,
					},
				},
			},
			expectPolicy: &bpfimav1alpha1.Policy{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "generic-new",
					CreationTimestamp: newTS,
				},
			},
		},
		// Verify that between two generic policies with the same creation timestamp the first in alphabetic order is chosen
		{
			name:      "Two generic policies present with same creation timestamp",
			nodeLabel: map[string]string{"color": "red"},
			policies: []bpfimav1alpha1.Policy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "green"},
					Spec: bpfimav1alpha1.PolicySpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"color": "green",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "generic-a",
						CreationTimestamp: oldTS,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "generic-b",
						CreationTimestamp: oldTS,
					},
				},
			},
			expectPolicy: &bpfimav1alpha1.Policy{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "generic-a",
					CreationTimestamp: oldTS,
				},
			},
		},
		// Verify that between two labelled policies the most recent is chosen
		{
			name:      "Two matching labelled policies present",
			nodeLabel: map[string]string{"color": "green"},
			policies: []bpfimav1alpha1.Policy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "green-new",
						CreationTimestamp: newTS,
					},
					Spec: bpfimav1alpha1.PolicySpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"color": "green",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "green-old",
						CreationTimestamp: oldTS,
					},
					Spec: bpfimav1alpha1.PolicySpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"color": "green",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "generic-old",
						CreationTimestamp: oldTS,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "generic-new",
						CreationTimestamp: newTS,
					},
				},
			},
			expectPolicy: &bpfimav1alpha1.Policy{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "green-new",
					CreationTimestamp: newTS,
				},
				Spec: bpfimav1alpha1.PolicySpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"color": "green",
						},
					},
				},
			},
		},
		// Verify that between two labelled policies the most recent is chosen (the node has two labels)
		{
			name:      "Two matching labelled policies present for different node labels",
			nodeLabel: map[string]string{"color": "green", "animal": "sheep"},
			policies: []bpfimav1alpha1.Policy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "sheep-new",
						CreationTimestamp: newTS,
					},
					Spec: bpfimav1alpha1.PolicySpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"animal": "sheep",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "green-old",
						CreationTimestamp: oldTS,
					},
					Spec: bpfimav1alpha1.PolicySpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"color": "green",
							},
						},
					},
				},
			},
			expectPolicy: &bpfimav1alpha1.Policy{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "sheep-new",
					CreationTimestamp: newTS,
				},
				Spec: bpfimav1alpha1.PolicySpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"animal": "sheep",
						},
					},
				},
			},
		},
		// Verify that between two labelled policies with same creation timestamp the first in alphabetic order is chosen
		// More recent generic policy is ignored
		{
			name:      "Two matching labelled policies present with same timestamp",
			nodeLabel: map[string]string{"color": "green", "animal": "sheep"},
			policies: []bpfimav1alpha1.Policy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "sheep",
						CreationTimestamp: oldTS,
					},
					Spec: bpfimav1alpha1.PolicySpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"animal": "sheep",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "green",
						CreationTimestamp: oldTS,
					},
					Spec: bpfimav1alpha1.PolicySpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"color": "green",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "generic-new",
						CreationTimestamp: newTS,
					},
				},
			},
			expectPolicy: &bpfimav1alpha1.Policy{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "green",
					CreationTimestamp: oldTS,
				},
				Spec: bpfimav1alpha1.PolicySpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"color": "green",
						},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := IdentifyCorrectPolicy(tc.policies, tc.nodeLabel)
			require.NoError(t, err)
			require.Equal(t, tc.expectPolicy, policy)
		})
	}
}
