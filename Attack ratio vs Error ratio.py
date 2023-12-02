import pandas as pd
import numpy as np

names = ['Timestamp', 'CAN_ID', 'DLC', 'DATA[0]', 'DATA[1]', 'DATA[2]', 'DATA[3]', 'DATA[4]', 'DATA[5]', 'DATA[6]',
         'DATA[7]', 'Flag']

df = pd.read_csv("D:\Korea University\Car-Hacking Data set\Testing(Car Hacking Dataset)\Fuzzy_dataset\Fuzzy_dataset.csv",
                 names=names)
can_id = df['CAN_ID'].values.tolist()
flag_id = df['Flag'].values.tolist()


def attack_count(flag_window):
    attacked = 0
    for i in range(0, len(flag_window)):
        if flag_window[i] == 'T':
            attacked = attacked + 1

    return attacked


def fre_count(adaptive_window):
    d = {x: adaptive_window.count(x) for x in adaptive_window}
    a = list(d.values())
    b = list(d.keys())
    return a, b


# variable allocation
N =100
i = 100
k = 1
range_1 = 100000


index_set = [0]*range_1
mean_filter = [0]*range_1
std_deviation_filter = [0]*range_1
mu_a = [0]* range_1
sigma_a = [0]* range_1
mu_s = [0]*range_1
sigma_s = [0]*range_1
M_i = [0]*range_1
attack_ratio = [0]*range_1
alpha_1 = [0]*range_1
alpha_2 = [0]*range_1
intrusion_detection = [0]*range_1
false_negative = [0]*range_1
false_positive = [0]*range_1
true_negative = [0]*range_1
true_positive = [0]*range_1

Error_rate = [0]*range_1



counter = 0
while counter < 100:
    adaptive_window = can_id[i - N:i]
    y, ids = fre_count(adaptive_window)

    flag_window = flag_id[i - N:i]
    M_i[k] = attack_count(flag_window)

    if M_i[k] > 0.0:
        k = k + 1
        i = i + 100
    else:
        # adaptive_window
        adaptive_window = can_id[i - N:i]
        # frequency count
        y, ids = fre_count(adaptive_window)
        # flag window
        flag_window = flag_id[i - N:i]
        # Number of Attack
        M_i[k] = attack_count(flag_window)
        # attack ratio
        attack_ratio[k] = M_i[k] / N
        # calculating mean and standard deviation for first window step
        mean_filter[k] = np.mean(y)
        std_deviation_filter[k] = np.std(y, ddof=1)
        # coping array
        use = np.array(mean_filter)
        use1 = np.array(std_deviation_filter)
        # calculating average and standard deviation of averages
        mu_a[k] = use[use != 0].mean()
        sigma_a[k] = use[use != 0].std()
        # calculating average and standard deviation of standard deviation
        mu_s[k] = use1[use1 != 0].mean()
        sigma_s[k] = use1[use1 != 0].std()
        # calculating: Reference value of normality
        mu_a_constant = mu_a[k]
        sigma_a_constant = sigma_a[k]
        mu_s_constant = mu_s[k]
        sigma_s_constant = sigma_s[k]

        k = k + 1
        i = i + 100
        counter = counter + 1


counter = 0
while counter < 25000:
    # adaptive_window
    adaptive_window = can_id[i - N:i]
    y, ids = fre_count(adaptive_window)

    flag_window = flag_id[i - N:i]
    M_i[k] = attack_count(flag_window)

    # attack ratio
    attack_ratio[k] = M_i[k] / N
    # calculating mean and standard deviation for first window step
    mean_filter[k] = np.mean(y)
    std_deviation_filter[k] = np.std(y, ddof=1)

    # calculating Z-score  with different equations
    alpha_1[k] = abs(mean_filter[k] - mu_a_constant) / sigma_a_constant
    alpha_2[k] = abs(std_deviation_filter[k] - mu_s_constant) / sigma_s_constant

    if ((alpha_1[k] <= 3) and (alpha_2[k] <= 3)):
        intrusion_detection[k] = 0
    else:
        intrusion_detection[k] = 1

    # False Negative : when current event is abnormal, but detector prediction = normal (no signalization of anomaly)
    if (attack_ratio[k] >= .02) and (intrusion_detection[k] == 0):
        false_negative[k] = 1
    # False Positive : when current event is normal, but detector prediction = abnormal (signalization of anomaly)
    if (attack_ratio[k] == 0) and (intrusion_detection[k] == 1):
        false_positive[k] = 1
    # True Negative : when current event is normal and detector prediction = normal (no signalization of anomaly)
    if (attack_ratio[k] == 0) and (intrusion_detection[k] == 0):
        true_negative[k] = 1
    # True Positive : when current event is abnormal and detector prediction = abnormal (signalization of anomaly).
    if (attack_ratio[k] >= .02) and (intrusion_detection[k] == 1):
        true_positive[k] = 1

    if (true_positive[k] + false_negative[k] + true_negative[k] + false_positive[k]) == 0:
        Error_rate[k] = 0
    else:
        Error_rate[k] = (false_positive[k] + false_negative[k]) / (
                    true_positive[k] + false_negative[k] + true_negative[k] + false_positive[k])

    k = k + 1
    i = i + 100
    counter = counter + 1



#mydf = pd.DataFrame(list(zip(attack_ratio,Error_rate)), columns = ['E^i (attack_ratio) ','Error_rate'])

#mydf.index = np.arange(1,len(mydf)+1)
#mydf.index.name = 'i'

#mydf.to_excel (r'D:\Excel for code\Fuzzy(Attack_ratio VS Error_rate_1000).xlsx', header=True)

