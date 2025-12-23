import matplotlib.pyplot as plt
import re
import sys
from collections import defaultdict
import numpy as np

def parse_and_plot(filename):
    # Data structure: 
    # data[type][phase] = [values...] (for end-to-end time)
    # bpf_data[type][phase][metric] = value (for internal metrics, we assume one average line per phase)
    data = defaultdict(lambda: defaultdict(list))
    bpf_data = defaultdict(lambda: defaultdict(dict))
    
    with open(filename, 'r') as f:
        lines = f.readlines()
        
    for line in lines:
        try:
            # Check for BPF Metric line
            # Type: Exec | Phase: BPF_First | Metric: Hash | Time: 123 ns
            if "Metric:" in line:
                parts = line.split('|')
                type_part = parts[0].split(':')[1].strip()
                phase_part = parts[1].split(':')[1].strip()
                metric_part = parts[2].split(':')[1].strip()
                time_str = parts[3].split(':')[1].strip().split()[0]
                time_val = int(time_str)
                
                bpf_data[type_part][phase_part][metric_part] = time_val
                
            # Check for standard Measure line
            # Type: Exec | Phase: BPF_First | Time: 12345 ns
            elif "Type:" in line and "Phase:" in line and "Time:" in line:
                parts = line.split('|')
                type_part = parts[0].split(':')[1].strip()
                phase_part = parts[1].split(':')[1].strip()
                time_str = parts[2].split(':')[1].strip().split()[0]
                time_val = int(time_str)
                
                data[type_part][phase_part].append(time_val)
                
        except (IndexError, ValueError) as e:
            # print(f"Skipping line: {line.strip()}")
            continue

    # Calculate Standard Averages
    averages = defaultdict(dict)
    phases = ["Baseline", "BPF_First", "BPF_Second"]
    
    for test_type, phases_dict in data.items():
        for phase in phases:
            vals = phases_dict.get(phase, [])
            if vals:
                avg = sum(vals) / len(vals)
                averages[test_type][phase] = avg
            else:
                averages[test_type][phase] = 0.0

    # Plot 1: End-to-End Performance (Existing)
    test_types = list(averages.keys())
    if not test_types:
        print("No valid data found to plot.")
        return

    for test_type in test_types:
        fig, ax = plt.subplots(figsize=(8, 6))
        
        phase_labels = ["Baseline", "BPF First\n(Cold)", "BPF Second\n(Warm)"]
        values = [averages[test_type].get(p, 0) for p in phases]
        
        bars = ax.bar(phase_labels, values, color=['slategrey', 'darkorange', 'forestgreen'])
        
        ax.set_title(f'{test_type} Performance (End-to-End)')
        ax.set_ylabel('Average Time (ns)')
        
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.0f}',
                    ha='center', va='bottom')
            
        baseline = averages[test_type].get("Baseline", 0)
        if baseline > 0:
            overhead_cold = ((values[1] - baseline) / baseline) * 100
            overhead_warm = ((values[2] - baseline) / baseline) * 100
            text_str = f"Overhead (Cold): {overhead_cold:.1f}%\nOverhead (Warm): {overhead_warm:.1f}%"
            ax.text(0.95, 0.95, text_str, transform=ax.transAxes, fontsize=10,
                    verticalalignment='top', horizontalalignment='right',
                    bbox=dict(boxstyle='round', facecolor='white', alpha=0.5))

        plt.tight_layout()
        output_file = f'perf_analysis_{test_type.lower()}.pdf'
        plt.savefig(output_file)
        print(f"Main plot saved to {output_file}")
        plt.close(fig)

    # Plot 2: BPF Internal Breakdown
    for test_type in test_types:
        if test_type not in bpf_data:
            continue
            
        fig, ax = plt.subplots(figsize=(10, 6))
        
        bpf_phases = ["BPF_First", "BPF_Second"]
        x_pos = np.arange(len(bpf_phases))
        width = 0.35
        
        # Metrics to display
        metrics = ["Deps", "Hash", "Extend"]
        colors = ['lightcoral', 'cornflowerblue', 'peru']
        
        # Prepare stacked data
        bottom = np.zeros(len(bpf_phases))
        
        for i, metric in enumerate(metrics):
            vals = []
            for phase in bpf_phases:
                vals.append(bpf_data[test_type][phase].get(metric, 0))
            
            p = ax.bar(x_pos, vals, width, bottom=bottom, label=metric, color=colors[i])
            # Add labels if segment is big enough
            # for rect in p:
            #    height = rect.get_height()
            #    if height > 0:
            #        ax.text(rect.get_x() + rect.get_width()/2., rect.get_y() + height/2.,
            #                f'{height:.0f}', ha='center', va='center', fontsize=8)
            
            bottom += np.array(vals)
            
        # Add Total line
        totals = []
        for phase in bpf_phases:
            totals.append(bpf_data[test_type][phase].get("Total", 0))
            
        # Draw total execution time as a line or separate bar?
        # Let's verify sum equality.
        # Often Total > Sum(components). The difference is overhead/other logic.
        # Let's plot the "Other" component.
        
        vals_other = []
        for i, phase in enumerate(bpf_phases):
             sum_comp = bottom[i]
             total_reported = totals[i]
             if total_reported > sum_comp:
                 vals_other.append(total_reported - sum_comp)
             else:
                 vals_other.append(0)
                 
        ax.bar(x_pos, vals_other, width, bottom=bottom, label="Other/Overhead", color='lightgray')
        
        # Final Total Labels
        for i, v in enumerate(totals):
             ax.text(x_pos[i], v, f"Total: {v}", ha='center', va='bottom', fontweight='bold')

        ax.set_xticks(x_pos)
        ax.set_xticklabels(["BPF First (Cold)", "BPF Second (Warm)"])
        ax.set_title(f'{test_type} Internal BPF Timing Breakdown')
        ax.set_ylabel('Time (ns)')
        ax.legend()
        
        plt.tight_layout()
        output_file_bpf = f'perf_analysis_{test_type.lower()}_bpf.pdf'
        plt.savefig(output_file_bpf)
        print(f"BPF breakdown plot saved to {output_file_bpf}")
        plt.close(fig)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        parse_and_plot(sys.argv[1])
    else:
        parse_and_plot('t.txt')
