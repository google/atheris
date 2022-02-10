import unittest

import atheris
from atheris.contrib.libprotobuf_mutator import atheris_libprotobuf_mutator
from atheris.src import fuzz_test_lib
from google3.google.protobuf import wrappers_pb2


@atheris.instrument_func
def simple_proto_comparison(msg):
  if msg.value == "abc":
    raise RuntimeError("Solved")


class AtherisLibprotobufMutatorTests(unittest.TestCase):

  def testSimpleProtoComparison(self):
    fuzz_test_lib.run_fuzztest(
        simple_proto_comparison,
        custom_setup=atheris_libprotobuf_mutator.Setup,
        setup_kwargs={"proto": wrappers_pb2.StringValue},
        expected_output=b"Solved",
        timeout=60)


if __name__ == "__main__":
  unittest.main()
