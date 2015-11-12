To generate a list of differentials, follow these steps:
1. `gen_graph.py` -- Generate graphs which show how the differences in the state propagate. Creates the following files:
  * `backward.gpickle`
  * `forward.gpickle`
  * `rev_backward.gpickle`
  * `rev_forward.gpickle`
2. `find_ids.py` -- Generate a list of impossible differentials. Creates the following files:
  * `ids.pickle`
3. `create_diff.py` -- Generate a list of differentials. This list is printed out.
