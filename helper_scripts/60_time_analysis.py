from utils import *
import pandas as pd


def process_time(time_str: str):
    if 'h' in time_str:
        hours = int(time_str[:time_str.find('h')])
        mins = int(time_str[time_str.find('h') + 1: time_str.find('m')])
        secs = int(time_str[time_str.find('m') + 1: time_str.find('s')])
        total = hours * 60 * 60 + mins * 60 + secs
        return str(total)
    elif 'm' in time_str:
        mins = int(time_str[:time_str.find('m')])
        secs = int(time_str[time_str.find('m') + 1: time_str.find('s')])
        total = mins * 60 + secs
        return str(total)
    elif 's' in time_str:
        return time_str.replace('s', '')
    else:
        return time_str


def process_output(data_row: str):
    bc_time_map = {}
    for line in data_row.split('\n'):
        if '.log' in line:
            bc_file = line[:line.find('.log')]
        elif '.call' in line:
            bc_file = line[:line.find('_36.call')]
        time_data = line[line.find('time ***') + 8: line.rfind('***')]
        time_data = process_time(time_data)
        if bc_file == '' or time_data == '':
            continue
        bc_time_map[bc_file] = time_data
    return bc_time_map


if __name__ == '__main__':
    time_pd = pd.DataFrame(
        columns=["Bitcode", "Fast SEG Build", "Fast PSA Checking", "Slow SEG Build", "Slow PSA Checking",
                 "Call SEG Build"])

    fast_dir = "/home/seal/Bugs_fast"
    slow_dir = "/home/seal/Bugs_slow"
    call_dir = "/home/seal/Calls_x86"

    time_grep = "grep -rni \"SEG-Building spends time\" *"

    _, output_info, _ = run_cmd(call_dir, time_grep)
    bc_time_map = process_output(output_info)
    bc_files = pd.Series(list(bc_time_map.keys()), name="Bitcode")
    time_pd.loc[:, 'Bitcode'] = bc_files

    for bc, time in bc_time_map.items():
        time_pd.loc[time_pd["Bitcode"] == bc, "Call SEG Build"] = int(time)

    print(time_pd)
    _, output_info, _ = run_cmd(fast_dir, time_grep)
    bc_time_map = process_output(output_info)
    for bc, time in bc_time_map.items():
        time_pd.loc[time_pd["Bitcode"] == bc, "Fast SEG Build"] = int(time)

    print(time_pd)
    _, output_info, _ = run_cmd(slow_dir, time_grep)
    bc_time_map = process_output(output_info)
    for bc, time in bc_time_map.items():
        time_pd.loc[time_pd["Bitcode"] == bc, "Slow SEG Build"] = int(time)

    print(time_pd)
    time_grep = "grep -rni \"PSA Checking spends time\" *"
    _, output_info, _ = run_cmd(fast_dir, time_grep)
    bc_time_map = process_output(output_info)
    for bc, time in bc_time_map.items():
        time_pd.loc[time_pd["Bitcode"] == bc, "Fast PSA Checking"] = int(time)

    print(time_pd)
    _, output_info, _ = run_cmd(slow_dir, time_grep)
    bc_time_map = process_output(output_info)
    for bc, time in bc_time_map.items():
        time_pd.loc[time_pd["Bitcode"] == bc, "Slow PSA Checking"] = int(time)

    print(time_pd)
    time_pd.to_csv("/home/seal/7_time_data.csv", index=False)
