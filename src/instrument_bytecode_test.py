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

    # Precondition: ideally the *original* code has no EXTENDED_ARG so that
    # instrumentation is what forces one to appear. On 3.14 the compiler emits
    # a NOT_TAKEN after the POP_JUMP_IF_*, which already pushes the jump over
    # 255 instructions, so just skip the precondition there and rely on the
    # post-conditions below.
    original_has_extended_arg = any(
        dis.opname[op] == "EXTENDED_ARG" for op in original_code.co_code[::2]
    )

    patched_code = instrument_bytecode.patch_code(
        original_code, trace_dataflow=True
    )
    patched_function = types.FunctionType(patched_code, globals())
    mockutils.UpdateCounterArrays()

    # The patched code must contain at least one EXTENDED_ARG.
    for op in patched_code.co_code[::2]:
      if dis.opname[op] == "EXTENDED_ARG":
        break
    else:
      self.fail("No EXTENDED_ARG instructions found in patched code.")
    if original_has_extended_arg:
      # Nothing more we can assert about *insertion*, but the behavioural
      # checks below still verify EXTENDED_ARG is handled correctly.
      pass

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

  def test_roundtrip_noop_rewrite(self):
    """Disassemble + reassemble with no instrumentation must be a no-op.

    For each function in a small zoo of control-flow shapes, build an
    Instrumentor, skip trace_*, and emit a code object. The new bytecode must
    decode to the same logical instruction stream as the original (modulo a
    trailing NOP that may be appended for past-the-end exception ranges).
    This catches any opcode/jump-arg/cache miscount independently of runtime
    behaviour.
    """

    def f_if(a, b):
      if a > b:
        return a
      return b

    def f_for(x):
      r = []
      for i in x:
        r.append(i)
      return r

    def f_tryexc(x):
      try:
        return x[0]
      except (KeyError, IndexError) as e:
        return e

    def f_with(x):
      with x as y:
        return y

    def f_match(x):
      match x:
        case 1:
          return "a"
        case [a, b]:
          return a + b
        case _:
          return None

    def f_gen():
      yield from (1, 2, 3)

    async def f_await(x):
      return await x

    async def f_asyncfor(x):
      async for i in x:
        pass

    def f_comp(x):
      return [i * 2 for i in x if i]

    def f_tstring(x):
      return f"value={x!r}"

    def normalise(code):
      out = []
      for i in dis.get_instructions(code):
        out.append((i.opname, i.argval))
      while out and out[-1][0] == "NOP":
        out.pop()
      return out

    for fn in [
        f_if,
        f_for,
        f_tryexc,
        f_with,
        f_match,
        f_gen,
        f_await,
        f_asyncfor,
        f_comp,
        f_tstring,
    ]:
      with self.subTest(fn=fn.__name__):
        inst = instrument_bytecode.Instrumentor(fn.__code__)
        new = inst.to_code()
        self.assertEqual(
            normalise(fn.__code__),
            normalise(new),
            f"round-trip changed bytecode of {fn.__name__}\n"
            f"old:\n{dis.Bytecode(fn.__code__).dis()}\n"
            f"new:\n{dis.Bytecode(new).dis()}",
        )

  def test_yield_from_send_jump(self):
    """Regression test: SEND's relative oparg must be rewritten.

    Before this was fixed, instrumenting `yield from` desynced SEND's jump
    target / return_offset from the actual END_SEND instruction. We exercise
    both SEND code paths:
      * the inlined-generator path (sub-generator return value), and
      * the StopIteration JUMPBY path (non-generator iterator).
    """

    def make_outer():
      def outer(it):
        # The result of `yield from` is the sub-iterator's StopIteration value
        # for generators, or None for plain iterators. Both paths flow through
        # SEND -> END_SEND.
        r = yield from it
        return ("done", r)

      return outer

    def sub_generator():
      yield 10
      yield 20
      return "rv"

    # --- Path 1: inlined generator (frame->return_offset) ---
    outer = make_outer()
    outer.__code__ = instrument_bytecode.patch_code(
        outer.__code__, trace_dataflow=False
    )
    mockutils.UpdateCounterArrays()

    g = outer(sub_generator())
    yielded = []
    try:
      while True:
        yielded.append(next(g))
    except StopIteration as e:
      ret = e.value
    self.assertEqual(yielded, [10, 20])
    self.assertEqual(ret, ("done", "rv"))

    # --- Path 2: non-generator iterator (StopIteration -> JUMPBY(oparg)) ---
    class PlainIter:
      """Iterator that is *not* a generator, so SEND can't inline it."""

      def __init__(self):
        self._it = iter([7, 8])

      def __iter__(self):
        return self

      def __next__(self):
        return next(self._it)

    outer2 = make_outer()
    outer2.__code__ = instrument_bytecode.patch_code(
        outer2.__code__, trace_dataflow=False
    )
    mockutils.UpdateCounterArrays()

    g = outer2(PlainIter())
    yielded = []
    try:
      while True:
        yielded.append(next(g))
    except StopIteration as e:
      ret = e.value
    self.assertEqual(yielded, [7, 8])
    self.assertEqual(ret, ("done", None))

  def test_await_send_jump(self):
    """SEND rewriting must also be correct for `await`."""
    import asyncio

    async def leaf():
      return 42

    async def root():
      x = await leaf()
      return x + 1

    root.__code__ = instrument_bytecode.patch_code(
        root.__code__, trace_dataflow=False
    )
    mockutils.UpdateCounterArrays()

    self.assertEqual(asyncio.run(root()), 43)

  def test_async_for(self):
    """`async for` exercises SEND/END_SEND/NOT_TAKEN/END_ASYNC_FOR together."""
    import asyncio

    class AIter:

      def __init__(self, n):
        self._n = n
        self._i = 0

      def __aiter__(self):
        return self

      async def __anext__(self):
        if self._i >= self._n:
          raise StopAsyncIteration
        self._i += 1
        return self._i

    async def consume(n):
      total = 0
      async for v in AIter(n):
        total += v
      return total

    consume.__code__ = instrument_bytecode.patch_code(
        consume.__code__, trace_dataflow=False
    )
    mockutils.UpdateCounterArrays()

    self.assertEqual(asyncio.run(consume(4)), 1 + 2 + 3 + 4)

    # Different iteration counts must produce distinguishable coverage.
    mockutils.clear_8bit_counters()
    asyncio.run(consume(1))
    c1 = list(mockutils.get_8bit_counters())
    mockutils.clear_8bit_counters()
    asyncio.run(consume(3))
    c3 = list(mockutils.get_8bit_counters())
    self.assertNotEqual(c1, c3)

  def test_send_target_stays_on_end_send(self):
    """After instrumentation, SEND must still jump exactly to END_SEND.

    This is the bytecode-level assertion behind test_yield_from_send_jump:
    if SEND's argval drifts, the runtime test above can pass by luck on some
    layouts but this one cannot.
    """
    if "SEND" not in dis.opmap or "END_SEND" not in dis.opmap:
      self.skipTest("SEND/END_SEND not present on this Python version")

    def outer(it):
      r = yield from it
      return r

    patched = instrument_bytecode.patch_code(
        outer.__code__, trace_dataflow=False
    )
    instrs = list(dis.get_instructions(patched))
    by_offset = {i.offset: i for i in instrs}
    sends = [i for i in instrs if i.opname == "SEND"]
    self.assertTrue(sends, "expected at least one SEND in `yield from`")
    for s in sends:
      self.assertEqual(
          by_offset[s.argval].opname,
          "END_SEND",
          f"SEND at {s.offset} targets {by_offset[s.argval].opname}, "
          "not END_SEND; frame->return_offset will be wrong.",
      )

  def test_end_async_for_target_stays_on_end_send(self):
    """3.14: END_ASYNC_FOR's backward oparg must keep pointing at END_SEND.

    The plain opcode ignores its oparg, but INSTRUMENTED_END_ASYNC_FOR (used
    when sys.monitoring is active) asserts
    (next_instr - oparg)->op.code == END_SEND. Atheris must therefore rewrite
    the oparg when it inserts instructions inside the async-for loop body.
    """
    if (
        "END_ASYNC_FOR" not in dis.opmap
        or dis.opmap["END_ASYNC_FOR"] not in dis.hasjrel
    ):
      self.skipTest("END_ASYNC_FOR has no jump arg on this Python version")

    async def consume(x):
      async for i in x:
        # A branch in the loop body so instrumentation is inserted between
        # END_SEND and END_ASYNC_FOR, which would desync an unrewritten oparg.
        if i:
          pass

    patched = instrument_bytecode.patch_code(
        consume.__code__, trace_dataflow=False
    )
    instrs = list(dis.get_instructions(patched))
    by_offset = {i.offset: i for i in instrs}
    eafs = [i for i in instrs if i.opname == "END_ASYNC_FOR"]
    self.assertTrue(eafs, "expected END_ASYNC_FOR in `async for`")
    for eaf in eafs:
      target = by_offset.get(eaf.argval)
      self.assertIsNotNone(
          target,
          f"END_ASYNC_FOR at {eaf.offset} targets offset {eaf.argval}, which "
          "is not even an instruction boundary; oparg was not rewritten.",
      )
      self.assertEqual(
          target.opname,
          "END_SEND",
          f"END_ASYNC_FOR at {eaf.offset} targets {target.opname}, not "
          "END_SEND; INSTRUMENTED_END_ASYNC_FOR's debug assert will fail.",
      )

  def test_small_int_const_compare(self):
    """3.14 emits LOAD_SMALL_INT for `if x == 5`; must hit const-cmp hook."""

    def const_compare(a):
      if a == 5:
        return True
      return False

    if not any(
        i.opname == "COMPARE_OP"
        for i in dis.get_instructions(const_compare.__code__)
    ):
      # Some optimisation levels may fold this away; bail rather than
      # mis-assert.
      self.skipTest("COMPARE_OP not present in compiled bytecode")

    const_compare.__code__ = instrument_bytecode.patch_code(
        const_compare.__code__, trace_control_flow=False, trace_dataflow=True
    )
    mockutils.UpdateCounterArrays()

    self.assertTrue(const_compare(5))
    self.mock_trace_cmp.assert_called_once()
    # is_const must be True so libFuzzer's const-cmp table is used.
    self.assertTrue(self.mock_trace_cmp.call_args[0][4])
    self.mock_const_cmp.assert_called_once()
    # The constant must be passed as the *first* argument.
    self.assertEqual(self.mock_const_cmp.call_args[0], (5, 5))

  def test_resume_with_depth_mask(self):
    """RESUME oparg may carry RESUME_OPARG_DEPTH1_MASK (0x4) on 3.13+.

    Post-yield RESUMEs inside one level of try/except get oparg `kind | 0x4`
    (e.g. RESUME 5). The instrumentor must:
      * still recognise the entry RESUME so `before_resume` flips, and
      * not mis-recognise a later RESUME-with-mask as a second entry RESUME
        (which would trip the `assert before_resume` in _disassemble).
    """

    def gen():
      x = yield 1
      yield x

    # Precondition: this construct produces at least one RESUME with the depth
    # bit set on the running interpreter; otherwise the test is uninteresting.
    instrs = list(dis.get_instructions(gen.__code__))
    if not any(
        i.opname == "RESUME" and i.arg is not None and i.arg & 0x4
        for i in instrs
    ):
      self.skipTest(
          "RESUME_OPARG_DEPTH1_MASK not set on this Python version"
      )

    patched = instrument_bytecode.patch_code(
        gen.__code__, trace_dataflow=False
    )
    gen.__code__ = patched
    mockutils.UpdateCounterArrays()

    mockutils.clear_8bit_counters()
    g = gen()
    self.assertEqual(next(g), 1)
    self.assertEqual(g.send("hi"), "hi")
    with self.assertRaises(StopIteration):
      next(g)
    self.assertTrue(
        any(c != 0 for c in mockutils.get_8bit_counters()),
        "no counters were incremented; entry RESUME was not recognised",
    )

  def test_for_loop_end_for_layout(self):
    """FOR_ITER's end-of-loop skip count is version-dependent.

    On 3.13 FOR_ITER does JUMPBY(oparg + 2) and skips END_FOR + POP_TOP; on
    3.14 it does JUMPBY(oparg + 1) and POP_ITER actually executes. Either way,
    after instrumentation FOR_ITER's argval must still point at END_FOR.
    """
    if "END_FOR" not in dis.opmap:
      self.skipTest("END_FOR not present on this Python version")

    def f(items):
      r = []
      for i in items:
        r.append(i)
      return r

    patched = instrument_bytecode.patch_code(
        f.__code__, trace_dataflow=False
    )
    instrs = list(dis.get_instructions(patched))
    by_offset = {i.offset: i for i in instrs}
    for_iters = [i for i in instrs if i.opname == "FOR_ITER"]
    self.assertTrue(for_iters)
    for fi in for_iters:
      self.assertEqual(
          by_offset[fi.argval].opname,
          "END_FOR",
          f"FOR_ITER at {fi.offset} targets {by_offset[fi.argval].opname}; "
          "the end-of-loop skip will land in the wrong place.",
      )

    # And it still has to actually run.
    f.__code__ = patched
    mockutils.UpdateCounterArrays()
    self.assertEqual(f([1, 2, 3]), [1, 2, 3])



if __name__ == "__main__":
  mockutils.main(verbosity=2)
