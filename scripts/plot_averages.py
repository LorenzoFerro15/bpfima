import matplotlib.pyplot as plt
import re
import sys
from collections import defaultdict

def parse_and_plot(filename):
    # Data structure: data[type][phase] = [values...]
    data = defaultdict(lambda: defaultdict(list))
    
    with open(filename, 'r') as f:
        lines = f.readlines()
        
    for line in lines:
        # Expected Format: Type: <Type> | Phase: <Phase> | Time: <Time> ns
        if "Type:" in line and "Phase:" in line and "Time:" in line:
            try:
                parts = line.split('|')
                # Parse Type
                type_part = parts[0].split(':')[1].strip()
                # Parse Phase
                phase_part = parts[1].split(':')[1].strip()
                # Parse Time (remove 'ns' and convert to int)
                time_str = parts[2].split(':')[1].strip().split()[0]
                time_val = int(time_str)
                
                data[type_part][phase_part].append(time_val)
            except (IndexError, ValueError) as e:
                print(f"Skipping malformed line: {line.strip()} ({e})")
                continue

    # Calculate Averages
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

    # Plotting
    test_types = list(averages.keys())
    if not test_types:
        print("No valid data found to plot.")
        return

    for test_type in test_types:
        fig, ax = plt.subplots(figsize=(8, 6))
        
        # Prepare data for this plot
        phase_labels = ["Baseline", "BPF First\n(Cold)", "BPF Second\n(Warm)"]
        values = [averages[test_type].get(p, 0) for p in phases]
        
        # Bar chart
        bars = ax.bar(phase_labels, values, color=['gray', 'orange', 'green'])
        
        ax.set_title(f'{test_type} Performance')
        ax.set_ylabel('Average Time (ns)')
        
        # Add labels on top of bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.0f}',
                    ha='center', va='bottom')
            
        # Calculate Overheads if Baseline exists
        baseline = averages[test_type].get("Baseline", 0)
        if baseline > 0:
            overhead_cold = ((values[1] - baseline) / baseline) * 100
            overhead_warm = ((values[2] - baseline) / baseline) * 100
            
            # Show overhead text
            text_str = f"Overhead (Cold): {overhead_cold:.1f}%\nOverhead (Warm): {overhead_warm:.1f}%"
            # Place text in top right
            ax.text(0.95, 0.95, text_str, transform=ax.transAxes, fontsize=10,
                    verticalalignment='top', horizontalalignment='right',
                    bbox=dict(boxstyle='round', facecolor='white', alpha=0.5))

        plt.tight_layout()
        output_file = f'perf_analysis_{test_type.lower()}.pdf'
        plt.savefig(output_file)
        print(f"Plot saved to {output_file}")
        plt.close(fig)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        parse_and_plot(sys.argv[1])
    else:
        parse_and_plot('t.txt')
