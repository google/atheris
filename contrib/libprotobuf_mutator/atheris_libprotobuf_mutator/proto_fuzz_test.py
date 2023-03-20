import unittest

import atheris
import atheris_libprotobuf_mutator
from atheris import fuzz_test_lib
from google.protobuf import wrappers_pb2


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
