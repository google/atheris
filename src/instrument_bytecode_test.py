import sys
import types
import unittest
from unittest import mock

# Mock the native extension, since it's not available in this test.
# This needs to be done before importing atheris.
mock_native = mock.MagicMock()
sys.modules["atheris.native"] = mock_native

import atheris
from atheris.src import instrument_bytecode
from atheris.src import version_dependent


class InstrumentBytecodeTest(unittest.TestCase):

  def setUp(self):
    # Reset the counter for each test
    mock_native._reserve_counter.side_effect = range(1000)

    # When the instrumented code is created, it captures the atheris module.
    # We need to ensure that when the instrumented code is executed, our
    # mocks are in place on that captured module object.
    # The easiest way to do this is to patch the module directly.
    self.mock_trace_branch = mock.MagicMock()
    self.mock_trace_cmp = mock.MagicMock()
    self.mock_hook_str = mock.MagicMock()

    # The instrumentor will add the real atheris module to the code object's
    # constants. When that code is executed, it will reference that module.
    # To intercept the calls, we need to patch the methods on the actual
    # atheris module.
    self.patches = [
        mock.patch.object(atheris, "_trace_branch", self.mock_trace_branch),
        mock.patch.object(atheris, "_trace_cmp", self.mock_trace_cmp),
        mock.patch.object(atheris, "_hook_str", self.mock_hook_str),
    ]
    for p in self.patches:
      p.start()
    self.addCleanup(lambda: [p.stop() for p in self.patches])

  def test_instrument_simple_function_no_dataflow(self):
    def simple_function(a, b):
      if a > b:
        return a
      else:
        return b

    original_code = simple_function.__code__
    patched_code = instrument_bytecode.patch_code(
        original_code, trace_dataflow=False)

    self.assertNotEqual(original_code, patched_code)
    self.assertIn("__ATHERIS_INSTRUMENTED__", patched_code.co_consts)

    patched_function = types.FunctionType(patched_code, globals())

    result = patched_function(5, 3)
    self.assertEqual(result, 5)
    self.mock_trace_branch.assert_called()
    self.mock_trace_cmp.assert_not_called()

    self.mock_trace_branch.reset_mock()

    result = patched_function(3, 5)
    self.assertEqual(result, 5)
    self.mock_trace_branch.assert_called()
    self.mock_trace_cmp.assert_not_called()

  def test_instrument_simple_function_with_dataflow(self):
    def simple_function(a, b):
      if a > b:
        return a
      else:
        return b

    self.mock_trace_cmp.side_effect = lambda obj1, obj2, op, counter, is_const: {
        ">": obj1 > obj2,
        "<": obj1 < obj2,
    }[instrument_bytecode.dis.cmp_op[op >> version_dependent.CMP_OP_SHIFT_AMOUNT]]

    original_code = simple_function.__code__
    patched_code = instrument_bytecode.patch_code(
        original_code, trace_dataflow=True)

    self.assertNotEqual(original_code, patched_code)
    self.assertIn("__ATHERIS_INSTRUMENTED__", patched_code.co_consts)

    patched_function = types.FunctionType(patched_code, globals())

    with self.subTest("first_branch"):
      result = patched_function(5, 3)
      self.assertEqual(result, 5)
      self.mock_trace_cmp.assert_called_once()
      # op for '>' is 4
      self.assertEqual(self.mock_trace_cmp.call_args[0][0], 5)
      self.assertEqual(self.mock_trace_cmp.call_args[0][1], 3)
      self.assertEqual(
          instrument_bytecode.dis.cmp_op[
              self.mock_trace_cmp.call_args[0][2]
              >> version_dependent.CMP_OP_SHIFT_AMOUNT
          ],
          ">",
      )
      self.assertEqual(self.mock_trace_cmp.call_args[0][4], False)  # is_const
      self.mock_trace_branch.assert_called()

      self.mock_trace_cmp.reset_mock()
      self.mock_trace_branch.reset_mock()

    with self.subTest("second_branch"):
      result = patched_function(3, 5)
      self.assertEqual(result, 5)
      self.mock_trace_cmp.assert_called_once()
      self.assertEqual(self.mock_trace_cmp.call_args[0][0], 3)
      self.assertEqual(self.mock_trace_cmp.call_args[0][1], 5)
      self.assertEqual(
          instrument_bytecode.dis.cmp_op[
              self.mock_trace_cmp.call_args[0][2]
              >> version_dependent.CMP_OP_SHIFT_AMOUNT
          ],
          ">",
      )
      self.assertEqual(self.mock_trace_cmp.call_args[0][4], False)  # is_const
      self.mock_trace_branch.assert_called()

  def test_instrument_const_compare(self):

    def const_compare(a):
      if a > 5:
        return True
      return False

    original_code = const_compare.__code__
    patched_code = instrument_bytecode.patch_code(
        original_code, trace_dataflow=True)
    patched_function = types.FunctionType(patched_code, globals())

    # The logic for const compare is that one of the operands is a const.
    # It should be instrumented.
    self.mock_trace_cmp.side_effect = lambda obj1, obj2, op, counter, is_const: {
        ">": obj1 > obj2,
        "<": obj1 < obj2,
    }[instrument_bytecode.dis.cmp_op[op >> version_dependent.CMP_OP_SHIFT_AMOUNT]]

    with self.subTest("true_branch"):
      self.assertTrue(patched_function(10))
      self.mock_trace_cmp.assert_called_once()
      self.assertEqual(self.mock_trace_cmp.call_args[0][0], 5)
      self.assertEqual(self.mock_trace_cmp.call_args[0][1], 10)
      self.assertEqual(self.mock_trace_cmp.call_args[0][4], True)  # is_const

    self.mock_trace_cmp.reset_mock()

    with self.subTest("false_branch"):
      self.assertFalse(patched_function(3))
      self.mock_trace_cmp.assert_called_once()
      self.assertEqual(self.mock_trace_cmp.call_args[0][0], 5)
      self.assertEqual(self.mock_trace_cmp.call_args[0][1], 3)
      self.assertEqual(self.mock_trace_cmp.call_args[0][4], True)  # is_const

  def test_instrument_func(self):
    self.mock_trace_cmp.side_effect = lambda obj1, obj2, op, counter, is_const: {
        ">": obj1 > obj2,
        "<": obj1 < obj2,
    }[instrument_bytecode.dis.cmp_op[op >> version_dependent.CMP_OP_SHIFT_AMOUNT]]


    @instrument_bytecode.instrument_func
    def to_be_instrumented(a, b):
      if a > b:
        return a
      return b

    self.assertIn("__ATHERIS_INSTRUMENTED__", to_be_instrumented.__code__.co_consts)

    self.assertEqual(to_be_instrumented(5, 3), 5)
    self.mock_trace_cmp.assert_called()
    self.mock_trace_branch.assert_called()


if __name__ == "__main__":
  unittest.main()
