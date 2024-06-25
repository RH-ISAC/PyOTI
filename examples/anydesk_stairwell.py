from examples.keys import stairwell
from pyoti.multis import Stairwell


sw = Stairwell(stairwell)
all_objects = sw.query_objects(
    query='rule.name in ["SUSP_AnyDesk_Compromised_Certificate_Jan24_1"]',
    page_size=150
)

label_lists = {}

for obj in all_objects:
    labels = obj['malEval']['labels']
    if labels:
        first_label = labels[0]
        if first_label not in label_lists:
            label_lists[first_label] = []
        label_lists[first_label].append(obj)

sorted_label_lists = dict(sorted(label_lists.items(), key=lambda item: len(item[1]), reverse=True))
