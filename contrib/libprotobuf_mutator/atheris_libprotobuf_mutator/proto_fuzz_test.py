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

  def testPostProcessor(self):
    # The post-processor rewrites every mutated message to the solving value, so
    # the comparison fires on the first input rather than waiting for the
    # mutator to stumble onto "abc" on its own. If the post-processor's edits
    # didn't make it back into the message the fuzzer feeds the harness, this
    # would time out instead.
    def setup_with_post_processor(argv, test_one_input, **kwargs):
      def force_value(msg, seed):
        del seed
        msg.value = "abc"

      atheris_libprotobuf_mutator.RegisterPostProcessor(
          wrappers_pb2.StringValue, force_value)
      return atheris_libprotobuf_mutator.Setup(argv, test_one_input, **kwargs)

    fuzz_test_lib.run_fuzztest(
        simple_proto_comparison,
        custom_setup=setup_with_post_processor,
        setup_kwargs={"proto": wrappers_pb2.StringValue},
        expected_output=b"Solved",
        timeout=60)


if __name__ == "__main__":
  unittest.main()
