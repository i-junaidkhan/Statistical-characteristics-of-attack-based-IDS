import pandas as pd
import numpy as np

names = ['Timestamp', 'CAN_ID', 'DLC', 'DATA[0]', 'DATA[1]', 'DATA[2]', 'DATA[3]', 'DATA[4]', 'DATA[5]', 'DATA[6]', 'DATA[7]', 'Flag']

df = pd.read_csv("G:\Korea University\Car_hacking_dataset\DoS_dataset.csv", names=names)
can_id = df['CAN_ID'].values.tolist()
flag_id = df['Flag'].values.tolist()

def attack_count(flag_window):
    return flag_window.count('T')

def fre_count(adaptive_window):
    return np.unique(adaptive_window, return_counts=True)[1]


N = 100
i = 100
range_1 = 25000

mean_filter = []
std_deviation_filter = []
M_i = []
attack_ratio = []

for j in range(range_1):
    adaptive_window = can_id[i - N:i]
    y = fre_count(adaptive_window)
    flag_window = flag_id[i - N:i]
    M_i.append(attack_count(flag_window))
    attack_ratio.append(M_i[j] / N)
    mean_filter.append(np.mean(y))
    std_deviation_filter.append(np.std(y, ddof=1))
    i += 100

mydf = pd.DataFrame(list(zip(attack_ratio, mean_filter, std_deviation_filter)), columns=['E^i (attack_ratio)', 'mu_i', 'sigma_i'])
mydf.head()
