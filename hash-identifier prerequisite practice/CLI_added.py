import argparse
from CombineAll import identify 

parser = argparse.ArgumentParser(description="Identify a hash algorithm")
parser.add_argument("hash")
args=parser.parse_args()
candidates = identify(args.hash)
for candidate in candidates:
    print(candidate)
