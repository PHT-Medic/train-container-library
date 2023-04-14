from pathlib import Path


def compare_files():

    dir = Path(__file__).parent
    with open(dir / "vorlars.py", "rb") as f:
        vorlars = f.read()

    with open(dir / "nachlars.py", "rb") as f:
        nachlars = f.read()

    print(vorlars == nachlars)


if __name__ == "__main__":
    compare_files()
