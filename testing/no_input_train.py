import os


if __name__ == "__main__":
    print(os.getcwd())
    print(os.listdir())

    with open("/opt/pht_results/results.text", "w") as f:
        f.write("test" * 1000)

    print("#################### DONE ####################")
