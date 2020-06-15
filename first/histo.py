data = "The Tower of London, officially Her Majesty's Royal Palace and Fortress of the Tower of London, " \
       "is a historic castle on the north bank of the River Thames in central London. It lies within the " \
       "London Borough of Tower Hamlets, which is separated from the eastern edge of the square mile of the " \
       "City of London by the open space known as Tower Hill. It was founded towards the end of 1066 as part of " \
       "the Norman Conquest of England. The White Tower, which gives the entire castle its name, was built by" \
       " William the Conqueror in 1078 and was a resented symbol of oppression, inflicted upon London by the new " \
       "ruling elite. The castle was also used as a prison from 1100 (Ranulf Flambard) until 1952 (Kray twins), " \
       "although that was not its primary purpose. A grand palace early in its history, it served as a royal residence" \
       ". As a whole, the Tower is a complex of several buildings set within two concentric rings of defensive walls" \
       " and a moat. There were several phases of expansion, mainly under kings Richard I, Henry III, and Edward I " \
       "in the 12th and 13th centuries. The general layout established by the late 13th century remains despite later " \
       "activity on the site."
data = data.replace(".", "")
data = data.replace(" ", "")
data = data.replace(",", "")
data = data.replace("'", "")
data = data.replace('(', "")
data = data.replace(")", "")
data = data.lower()


def count_elements(seq) -> dict:
     """Tally elements from `seq`."""
     hist = {}
     for i in seq:
         hist[i] = hist.get(i, 0) + 1
     return hist


def ascii_histogram(seq) -> None:
    """A horizontal frequency-table/histogram plot."""
    counted = count_elements(seq)
    for k in sorted(counted):
        print('{0} {1}'.format(k, '+' * counted[k]))



hist=count_elements(data)
ascii_histogram(data)  # look in terminal

import matplotlib.pyplot as plt
plt.bar(hist.keys(), hist.values())
plt.show()
