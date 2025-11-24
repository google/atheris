import dis
import importlib
import sys
import types
import unittest
from unittest import mock

# Mock the native extension, since it's not available in this test.
# This needs to be done before importing atheris.
import atheris

from atheris import instrument_bytecode
from atheris import version_dependent
from atheris.mock_libfuzzer import mockutils


class InstrumentBytecodeTest(mockutils.MockLibFuzzerMixin, unittest.TestCase):
  def setUp(self):
    super(InstrumentBytecodeTest, self).setUp()

    self.original_trace_cmp = atheris._trace_cmp
    self.mock_trace_cmp = mock.MagicMock(wraps=self.original_trace_cmp)
    atheris._trace_cmp = self.mock_trace_cmp

  def tearDown(self):
    atheris._trace_cmp = self.original_trace_cmp
    super(InstrumentBytecodeTest, self).tearDown()

  def test_instrument_simple_function_no_dataflow(self):
    def simple_function(a, b):
      if a > b:
        return a
      else:
        return b

    original_code = simple_function.__code__
    patched_code = instrument_bytecode.patch_code(
        original_code, trace_dataflow=False
    )
    mockutils.UpdateCounterArrays()

    self.assertNotEqual(original_code, patched_code)
    self.assertIn("__ATHERIS_INSTRUMENTED__", patched_code.co_consts)

    patched_function = types.FunctionType(patched_code, globals())

    result = patched_function(5, 3)
    self.assertEqual(result, 5)
    self.assertCountersAre([1, 1])
    self.mock_cmp.assert_not_called()
    self.mock_const_cmp.assert_not_called()

    result = patched_function(3, 5)
    self.assertEqual(result, 5)
    self.assertCountersAre([2, 1, 1])
    self.mock_cmp.assert_not_called()
    self.mock_const_cmp.assert_not_called()

  def test_instrument_simple_function_with_dataflow(self):
    def simple_function(a, b):
      if a > b:
        return a
      else:
        return b

    original_code = simple_function.__code__
    patched_code = instrument_bytecode.patch_code(
        original_code, trace_dataflow=True
    )
    mockutils.UpdateCounterArrays()

    self.assertNotEqual(original_code, patched_code)
    self.assertIn("__ATHERIS_INSTRUMENTED__", patched_code.co_consts)

    patched_function = types.FunctionType(patched_code, globals())

    with self.subTest("first_branch"):
      result = patched_function(5, 3)
      self.assertEqual(result, 5)
      self.assertCountersAre([1, 1])
      self.mock_trace_cmp.assert_called_once()
      # op for '>' is 4
      self.assertEqual(self.mock_trace_cmp.call_args[0][0], 5)
      self.assertEqual(self.mock_trace_cmp.call_args[0][1], 3)
      self.assertEqual(self.mock_cmp.call_args[0], (5, 3))
      self.assertEqual(
          instrument_bytecode.dis.cmp_op[
              self.mock_trace_cmp.call_args[0][2]
              >> version_dependent.CMP_OP_SHIFT_AMOUNT
          ],
          ">",
      )
      self.assertEqual(self.mock_trace_cmp.call_args[0][4], False)  # is_const

      self.mock_trace_cmp.reset_mock()
      self.mock_const_cmp.reset_mock()

    with self.subTest("second_branch"):
      result = patched_function(3, 5)
      self.assertCountersAre([2, 1, 1])
      self.assertEqual(result, 5)
      self.mock_trace_cmp.assert_called_once()
      self.assertEqual(self.mock_trace_cmp.call_args[0][0], 3)
      self.assertEqual(self.mock_trace_cmp.call_args[0][1], 5)
      self.assertEqual(self.mock_cmp.call_args[0], (3, 5))
      self.assertEqual(
          instrument_bytecode.dis.cmp_op[
              self.mock_trace_cmp.call_args[0][2]
              >> version_dependent.CMP_OP_SHIFT_AMOUNT
          ],
          ">",
      )
      self.assertEqual(self.mock_trace_cmp.call_args[0][4], False)  # is_const

  def test_instrument_const_compare(self):
    def const_compare(a):
      if 5 < a:
        return True
      return False

    original_code = const_compare.__code__
    patched_code = instrument_bytecode.patch_code(
        original_code, trace_control_flow=False, trace_dataflow=True
    )
    patched_function = types.FunctionType(patched_code, globals())
    mockutils.UpdateCounterArrays()

    with self.subTest("true_branch"):
      self.assertTrue(patched_function(10))
      self.mock_trace_cmp.assert_called_once()
      self.assertEqual(self.mock_trace_cmp.call_args[0][0], 5)
      self.assertEqual(self.mock_trace_cmp.call_args[0][1], 10)
      self.assertEqual(self.mock_trace_cmp.call_args[0][4], True)  # is_const
      self.mock_const_cmp.assert_called_once()
      self.assertEqual(self.mock_const_cmp.call_args[0], (5, 10))

    self.mock_trace_cmp.reset_mock()
    self.mock_const_cmp.reset_mock()

    with self.subTest("false_branch"):
      self.assertFalse(patched_function(3))
      self.mock_trace_cmp.assert_called_once()
      self.assertEqual(self.mock_trace_cmp.call_args[0][0], 5)
      self.assertEqual(self.mock_trace_cmp.call_args[0][1], 3)
      self.assertEqual(self.mock_trace_cmp.call_args[0][4], True)  # is_const
      self.mock_const_cmp.assert_called_once()
      self.assertEqual(self.mock_const_cmp.call_args[0], (5, 3))

  def test_instrument_reverse_const_compare(self):
    def const_compare(a):
      if a > 5:
        return True
      return False

    original_code = const_compare.__code__
    patched_code = instrument_bytecode.patch_code(
        original_code, trace_control_flow=False, trace_dataflow=True
    )
    patched_function = types.FunctionType(patched_code, globals())
    mockutils.UpdateCounterArrays()

    with self.subTest("true_branch"):
      self.assertTrue(patched_function(10))
      self.mock_trace_cmp.assert_called_once()
      self.assertEqual(self.mock_trace_cmp.call_args[0][0], 5)
      self.assertEqual(self.mock_trace_cmp.call_args[0][1], 10)
      self.assertEqual(self.mock_trace_cmp.call_args[0][4], True)  # is_const
      self.mock_const_cmp.assert_called_once()
      self.assertEqual(self.mock_const_cmp.call_args[0], (5, 10))

    self.mock_trace_cmp.reset_mock()
    self.mock_const_cmp.reset_mock()

    with self.subTest("false_branch"):
      self.assertFalse(patched_function(3))
      self.mock_trace_cmp.assert_called_once()
      self.assertEqual(self.mock_trace_cmp.call_args[0][0], 5)
      self.assertEqual(self.mock_trace_cmp.call_args[0][1], 3)
      self.assertEqual(self.mock_trace_cmp.call_args[0][4], True)  # is_const
      self.mock_const_cmp.assert_called_once()
      self.assertEqual(self.mock_const_cmp.call_args[0], (5, 3))

    @instrument_bytecode.instrument_func
    def to_be_instrumented(a, b):
      if a > b:
        return a
      return b
    mockutils.UpdateCounterArrays()

    self.assertIn(
        "__ATHERIS_INSTRUMENTED__", to_be_instrumented.__code__.co_consts
    )

    self.assertEqual(to_be_instrumented(5, 3), 5)
    self.mock_trace_cmp.assert_called()

  def test_instrument_strcmp(self):
    def str_cmp(a, b):
      if a == b:
        return "equal"
      return "notequal"

    original_code = str_cmp.__code__
    patched_code = instrument_bytecode.patch_code(
        original_code, trace_dataflow=True
    )
    patched_function = types.FunctionType(patched_code, globals())
    mockutils.UpdateCounterArrays()

    self.assertIn("__ATHERIS_INSTRUMENTED__", patched_code.co_consts)

    def test_impl(left: str | bytes, right: str | bytes):
      if left.__class__ != right.__class__:
        raise TypeError(
            "Expected left and right to be of the same type; got"
            f" left={left.__class__} but right={right.__class__}"
        )
      if isinstance(left, str) and isinstance(right, str):
        left_bytes = left.encode("utf-8")
        right_bytes = right.encode("utf-8")
      else:
        left_bytes = left
        right_bytes = right

      expected_result = "equal" if left_bytes == right_bytes else "notequal"

      self.assertEqual(patched_function(left, right), expected_result)

      # Atheris should first perform a numeric comparison on string length
      self.mock_cmp.assert_called()
      self.assertEqual(
          self.mock_cmp.call_args[0], (len(left_bytes), len(right_bytes))
      )

      if len(left_bytes) != len(right_bytes):
        self.mock_memcmp.assert_not_called()
        return

      # If the string lengths matched, it should now perform a full comparison
      # of the string bytes.
      self.mock_memcmp.assert_called()

      actual_left = self.mock_memcmp.call_args[0][1]
      actual_right = self.mock_memcmp.call_args[0][2]
      actual_n = self.mock_memcmp.call_args[0][3]
      actual_result = self.mock_memcmp.call_args[0][4]

      self.assertEqual(left_bytes, actual_left)
      self.assertEqual(right_bytes, actual_right)
      self.assertEqual(len(left), actual_n)
      if left_bytes == right_bytes:
        self.assertEqual(actual_result, 0)
      elif left_bytes > right_bytes:
        self.assertGreater(actual_result, 0)
      else:
        self.assertLess(actual_result, 0)

      self.mock_cmp.reset_mock()
      self.mock_memcmp.reset_mock()
      self.mock_trace_cmp.reset_mock()
      self.mock_memcmp.reset_mock()

    test_impl("foo", "foo")
    test_impl("foo", "bar")
    test_impl("bar", "foo")
    test_impl(b"foo", b"foo")
    test_impl(b"foo", b"bar")
    test_impl(b"one", b"four")

  def test_instrument_elif(self):
    def function_with_elif(a):
      if a == 1:
        return 10
      elif a == 2:
        return 20
      else:
        return 30

    original_code = function_with_elif.__code__
    patched_code = instrument_bytecode.patch_code(
        original_code, trace_dataflow=True
    )
    patched_function = types.FunctionType(patched_code, globals())
    mockutils.UpdateCounterArrays()

    with self.subTest("if branch"):
      self.assertEqual(patched_function(1), 10)
      # Entry-point and first branch taken.
      self.assertCountersAre([1, 1])
      self.mock_trace_cmp.assert_called()
      self.mock_trace_cmp.reset_mock()

    with self.subTest("elif branch"):
      self.assertEqual(patched_function(2), 20)
      # Entry-point taken again (2); 2nd branch taken (1),
      # then the first sub-branch (1); plus the original (1) from the first
      # branch still there..
      self.assertCountersAre([2, 1, 1, 1])
      self.mock_trace_cmp.assert_called()
      self.mock_trace_cmp.reset_mock()

    with self.subTest("else branch"):
      self.assertEqual(patched_function(3), 30)
      # Entry-point taken again (3); 2nd branch taken again (2);
      # then the 2nd sub-branch (1); plus the original (1) from the first
      # branch and (1) from the 2nd sub-branch still there.
      self.assertCountersAre([3, 2, 1, 1, 1])
      self.mock_trace_cmp.assert_called()

  def test_instrument_for_loop(self):
    def function_with_for_loop(items):
      result = []
      for i in items:
        result.append(i)
      return result

    original_code = function_with_for_loop.__code__
    patched_code = instrument_bytecode.patch_code(
        original_code, trace_dataflow=False
    )
    patched_function = types.FunctionType(patched_code, globals())
    mockutils.UpdateCounterArrays()

    with self.subTest("empty list"):
      self.assertEqual(patched_function([]), [])
      # Entry-point (1), for-loop conditional (1), return block (1).
      self.assertCountersAre([1, 1, 1])

    with self.subTest("non-empty list"):
      mockutils.clear_8bit_counters()
      self.assertEqual(patched_function([1, 2, 3]), [1, 2, 3])
      # Entry-point (1), for-loop conditional (4), for-loop body (3),
      # return block (1).
      self.assertCountersAre([1, 4, 3, 1])

  def test_instrument_while_loop(self):
    def function_with_while_loop(count):
      i = 0
      while i < count:
        i += 1
      return i

    original_code = function_with_while_loop.__code__
    patched_code = instrument_bytecode.patch_code(
        original_code, trace_dataflow=True
    )
    patched_function = types.FunctionType(patched_code, globals())
    mockutils.UpdateCounterArrays()

    with self.subTest("zero iterations"):
      self.assertEqual(patched_function(0), 0)
      self.assertIn(1, mockutils.get_8bit_counters())
      self.mock_trace_cmp.assert_called()
      self.mock_trace_cmp.reset_mock()

    with self.subTest("multiple iterations"):
      self.assertEqual(patched_function(3), 3)
      self.assertIn(3, mockutils.get_8bit_counters())
      self.mock_trace_cmp.assert_called()

  def test_extended_arg(self):
    """Tests that we can handle the insertion of new EXTENDED_ARG instructions."""

    # Adding an instruction will require a new EXTENDED_ARG instruction.
    def near_extended_arg(x, y):
      """This function has a jump of length 255."""
      if x > y:
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        pass
        return x
      return y

    original_code = near_extended_arg.__code__

    # Ensure that the original code does not contain any EXTENDED_ARG
    # instructions.
    for inst in original_code.co_code:
      self.assertNotEqual(dis.opname[inst], "EXTENDED_ARG")

    patched_code = instrument_bytecode.patch_code(
        original_code, trace_dataflow=True
    )
    patched_function = types.FunctionType(patched_code, globals())
    mockutils.UpdateCounterArrays()

    # Ensure that the patched code contains EXTENDED_ARG instructions.
    for inst in patched_code.co_code:
      if dis.opname[inst] == "EXTENDED_ARG":
        break
    else:
      self.fail("No EXTENDED_ARG instructions found in patched code.")

    mockutils.clear_8bit_counters()
    self.assertEqual(patched_function(1, 2), 2)
    first_counters = mockutils.get_8bit_counters()

    mockutils.clear_8bit_counters()
    self.assertEqual(patched_function(3, 1), 3)
    second_counters = mockutils.get_8bit_counters()

    # Assert that we detected different branches being taken
    self.assertNotEqual(first_counters, second_counters)

  def test_exception(self):
    def raise_exception():
      try:
        raise ValueError("test")
      except ValueError:
        pass

    original_code = raise_exception.__code__
    patched_code = instrument_bytecode.patch_code(
        original_code, trace_dataflow=True
    )
    raise_exception.__code__ = patched_code

    raise_exception()

  def test_reference_lineup(self):
    """This is a regression test for a previous failure with exception+loop."""

    class Raiser:

      def __radd__(self, other):
        raise StopIteration("Stop!")

    tup = (1, 2, 3, Raiser(), 4)
    func_out = 0
    branch_hit = False

    def reproducer():
      nonlocal func_out, branch_hit
      for val in tup:
        try:
          func_out += val
        except StopIteration:
          break
      if True:  # pylint: disable=using-constant-test
        branch_hit = True

    patched = instrument_bytecode.patch_code(
        reproducer.__code__, trace_dataflow=False
    )
    reproducer.__code__ = patched

    reproducer()

    self.assertEqual(func_out, 6)
    self.assertEqual(branch_hit, True)

  def test_six(self):
    """This is a regression test for a previous failure."""

    class _SixMetaPathImporter(object):

      def __init__(self):
        self.known_modules = {"foo": "bar"}

      def __get_module(self, fullname):
        try:
          return self.known_modules[fullname]
        except KeyError as e:
          raise ImportError(
              "This loader does not know module " + fullname
          ) from e

      def get_module(self, fullname):
        return self.__get_module(fullname)

    func = _SixMetaPathImporter._SixMetaPathImporter__get_module
    original_code = func.__code__

    patched_code = instrument_bytecode.patch_code(
        original_code, trace_dataflow=True
    )
    func.__code__ = patched_code

    _SixMetaPathImporter.get_module.__code__ = instrument_bytecode.patch_code(
        _SixMetaPathImporter.get_module.__code__, trace_dataflow=True
    )

    self.assertEqual(
        _SixMetaPathImporter()._SixMetaPathImporter__get_module("foo"), "bar"
    )
    with self.assertRaises(ImportError):
      _SixMetaPathImporter()._SixMetaPathImporter__get_module("baz")

    self.assertEqual(_SixMetaPathImporter().get_module("foo"), "bar")
    with self.assertRaises(ImportError):
      _SixMetaPathImporter().get_module("baz")

  def test_exception_end_range(self):
    """Test for past-the-end exception table entries.

    This test verifies that Atheris correctly handles the situation where an
    exception table entry's end_offset points to the past-the-end index of
    the code. I was unable to get Python to generate such code on its own, but
    it is theoretically valid, so this test covers that case by manually
    constructing such code.
    """

    ctr = 0

    def do_nothing():
      pass

    def with_function(termination):
      nonlocal ctr
      r = RuntimeError("test")

      try:
        do_nothing()
      except:  # pylint: disable=bare-except  # noqa: E722
        pass

      if ctr == termination:
        return
      ctr += 1
      raise r

    code = with_function.__code__

    # Manually modify the exceptiontable to send everything to the first target.
    # This turns the function into an extremely weird loop - it keeps jumping
    # back to the `except: pass` block until ctr == termination.
    original_et = version_dependent.parse_exceptiontable(code.co_exceptiontable)
    first_target = original_et.entries[0].target

    entry = version_dependent.ExceptionTableEntry(
        0, len(code.co_code), first_target, 0, False
    )
    generated_et = version_dependent.generate_exceptiontable(code, [entry])

    with_function.__code__ = version_dependent.get_code_object(
        with_function.__code__,
        with_function.__code__.co_stacksize,
        with_function.__code__.co_code,
        with_function.__code__.co_consts,
        with_function.__code__.co_names,
        with_function.__code__.co_linetable,
        generated_et,
    )
    with_function(5)

    # Makes sure our weird patch was successful.
    # If this fails, the test is broken, not necessarily Atheris.
    self.assertEqual(ctr, 5)

    ctr = 0

    # Now, make sure Atheris handles the past-the-end range correctly.
    patched_code = instrument_bytecode.patch_code(
        with_function.__code__, trace_dataflow=True, trace_control_flow=True
    )
    with_function.__code__ = patched_code
    with_function(13)
    self.assertEqual(ctr, 13)

  def test_cmp_op(self):
    def compare_eq(x, y):
      return x == y

    def compare_ne(x, y):
      return x != y

    def compare_lt(x, y):
      return x < y

    def compare_gt(x, y):
      return x > y

    def compare_le(x, y):
      return x <= y

    def compare_ge(x, y):
      return x >= y

    for func in [
        compare_eq,
        compare_ne,
        compare_lt,
        compare_gt,
        compare_le,
        compare_ge,
    ]:
      original_code = func.__code__
      patched_code = instrument_bytecode.patch_code(
          original_code, trace_dataflow=True
      )
      func.__code__ = patched_code

    with self.subTest("equal"):
      val = compare_eq(1, 2)
      self.assertEqual(val, False)
      self.mock_trace_cmp.assert_called_once()
      op_arg = self.mock_trace_cmp.call_args[0][2]
      computed_op = instrument_bytecode.dis.cmp_op[
          op_arg >> version_dependent.CMP_OP_SHIFT_AMOUNT
      ]
      self.assertEqual(computed_op, "==")
      self.mock_trace_cmp.reset_mock()

    with self.subTest("not_equal"):
      val = compare_ne(1, 2)
      self.assertEqual(val, True)
      self.mock_trace_cmp.assert_called_once()
      op_arg = self.mock_trace_cmp.call_args[0][2]
      computed_op = instrument_bytecode.dis.cmp_op[
          op_arg >> version_dependent.CMP_OP_SHIFT_AMOUNT
      ]
      self.assertEqual(computed_op, "!=")
      self.mock_trace_cmp.reset_mock()

    with self.subTest("less"):
      val = compare_lt(1, 2)
      self.assertEqual(val, True)
      self.mock_trace_cmp.assert_called_once()
      op_arg = self.mock_trace_cmp.call_args[0][2]
      computed_op = instrument_bytecode.dis.cmp_op[
          op_arg >> version_dependent.CMP_OP_SHIFT_AMOUNT
      ]
      self.assertEqual(computed_op, "<")
      self.mock_trace_cmp.reset_mock()

    with self.subTest("greater"):
      val = compare_gt(1, 2)
      self.assertEqual(val, False)
      self.mock_trace_cmp.assert_called_once()
      op_arg = self.mock_trace_cmp.call_args[0][2]
      computed_op = instrument_bytecode.dis.cmp_op[
          op_arg >> version_dependent.CMP_OP_SHIFT_AMOUNT
      ]
      self.assertEqual(computed_op, ">")
      self.mock_trace_cmp.reset_mock()

    with self.subTest("less_equal"):
      val = compare_le(1, 2)
      self.assertEqual(val, True)
      self.mock_trace_cmp.assert_called_once()
      op_arg = self.mock_trace_cmp.call_args[0][2]
      computed_op = instrument_bytecode.dis.cmp_op[
          op_arg >> version_dependent.CMP_OP_SHIFT_AMOUNT
      ]
      self.assertEqual(computed_op, "<=")
      self.mock_trace_cmp.reset_mock()

    with self.subTest("greater_equal"):
      val = compare_ge(1, 2)
      self.assertEqual(val, False)
      self.mock_trace_cmp.assert_called_once()
      op_arg = self.mock_trace_cmp.call_args[0][2]
      computed_op = instrument_bytecode.dis.cmp_op[
          op_arg >> version_dependent.CMP_OP_SHIFT_AMOUNT
      ]
      self.assertEqual(computed_op, ">=")
      self.mock_trace_cmp.reset_mock()

  def test_instructions_before_resume(self):
    class SuperClazz:

      def setUp(self):  # pylint: disable=g-missing-super-call
        self.buf = None
        pass

    class Clazz(SuperClazz):

      def setUp(self):
        super().setUp()

        x = lambda hint: self.buf  # noqa: E731  # type: ignore
        del x

    # Verify that the first instruction is not a RESUME instruction,
    # otherwise this test is unhelpful.
    instrs = version_dependent.get_instructions(Clazz.setUp.__code__)
    self.assertNotEqual(list(instrs)[0].opname, "RESUME")

    instrument_bytecode.instrument_func(Clazz.setUp)

    instance = Clazz()
    instance.setUp()

  def test_idempotent_instrument(self):
    @atheris.instrument_func
    @atheris.instrument_func
    @atheris.instrument_func
    def func(x, y):
      return x * y

    consts = func.__code__.co_consts
    self.assertEqual(consts.count("__ATHERIS_INSTRUMENTED__"), 1)

    mockutils.UpdateCounterArrays()
    mockutils.clear_8bit_counters()
    self.assertEqual(func(2, 3), 6)
    self.assertCountersAre([1])


if __name__ == "__main__":
  mockutils.main(verbosity=2)
