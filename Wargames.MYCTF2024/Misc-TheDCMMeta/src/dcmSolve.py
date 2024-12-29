listt = [25, 10, 0, 3, 17, 19, 23, 27, 4, 13, 20, 8, 24, 21, 31, 15, 7, 29, 6, 1, 9, 30, 22, 5, 28, 18, 26, 11, 2, 14, 16, 12]
stree = "f63acd3b78127c1d7d3e700b55665354"
print(len(listt), len(stree))

straft = ""

for i in listt:
    straft += stree[i]

print(straft, len(straft))
