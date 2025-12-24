import sys
import json

def main():
    if len(sys.argv) != 4:
        sys.exit(1)

    test_type = sys.argv[1]
    phase = sys.argv[2]
    try:
        map_id = int(sys.argv[3])
    except ValueError:
        sys.exit(1)

    try:
        data = json.load(sys.stdin)
        target = None
        
        if isinstance(data, list):
            for elem in data:
                key = elem.get('key')
                if 'formatted' in elem and 'key' in elem['formatted']:
                    key = elem['formatted']['key']
                
                try:
                    k_val = -1
                    if isinstance(key, int):
                        k_val = key
                    elif isinstance(key, str):
                        k_val = int(key, 0)
                    
                    if k_val == map_id:
                        vals_list = None
                        if 'formatted' in elem and 'values' in elem['formatted']:
                             vals_list = elem['formatted']['values']
                        elif 'values' in elem:
                             vals_list = elem['values']

                        if vals_list:
                            agg = {'count': 0, 'total_time': 0, 'deps_time': 0, 'measure_time': 0, 'hash_time': 0, 'extend_time': 0}
                            for cpu_entry in vals_list:
                                val = cpu_entry.get('value')
                                if isinstance(val, dict):
                                    agg['count'] += int(val.get('count', 0))
                                    agg['total_time'] += int(val.get('total_time', 0))
                                    agg['deps_time'] += int(val.get('deps_time', 0))
                                    agg['measure_time'] += int(val.get('measure_time', 0))
                                    agg['hash_time'] += int(val.get('hash_time', 0))
                                    agg['extend_time'] += int(val.get('extend_time', 0))
                            target = agg
                        else:
                            if 'formatted' in elem:
                                target = elem['formatted'].get('value')
                            else:
                                target = elem.get('value')
                        break
                except (ValueError, TypeError):
                    continue

        if target:
            count = int(target.get('count', 0))
            if count > 0:
                total = int(target.get('total_time', 0)) // count
                deps = int(target.get('deps_time', 0)) // count
                measure = int(target.get('measure_time', 0)) // count
                hash_t = int(target.get('hash_time', 0)) // count
                extend = int(target.get('extend_time', 0)) // count
                
                print(f'Type: {test_type} | Phase: {phase} | Metric: Total | Time: {total} ns')
                print(f'Type: {test_type} | Phase: {phase} | Metric: Deps | Time: {deps} ns')
                print(f'Type: {test_type} | Phase: {phase} | Metric: Measure | Time: {measure} ns')
                print(f'Type: {test_type} | Phase: {phase} | Metric: Hash | Time: {hash_t} ns')
                print(f'Type: {test_type} | Phase: {phase} | Metric: Extend | Time: {extend} ns')
            else:
                pass
        else:
            pass

    except Exception:
        pass

if __name__ == "__main__":
    main()
