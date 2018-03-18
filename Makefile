python3=python3

test:
	$(python3) -m doctest $(V) taintedstr.py
