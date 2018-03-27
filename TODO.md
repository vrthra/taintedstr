# Things to do

* Move the Comparison global to a tstr member. Then each
  time a new tstr is generated, assign the Comparison (ref) from
  the parent member. This way, comparison is traced only within
  tainted strings from that input, and there is no need to explicitly
  clear it.

* Rather than switch every comparison to EQ in tainteds str, capture
  every operation in the string with its own code, and arguments.
  Then later, process them to determine the actual comparions, and
  covert them to EQ where useful, filtering out the remaining.
  This way, we can remove the global Ins and IComparisons
