import importlib
import sys
import types
import unittest
from unittest import mock

# Mock the native extension, since it's not available in this test.
# This needs to be done before importing atheris.
mock_native = mock.MagicMock()
sys.modules["atheris.native"] = mock_native
import atheris

if sys.version_info >= (3, 12):
  from atheris.src import clean_instrument_bytecode as instrument_bytecode
else:
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

    def mock_trace_cmp_side_effect(obj1, obj2, op, counter, is_const):
      del counter, is_const
      op = instrument_bytecode.dis.cmp_op[
          op >> version_dependent.CMP_OP_SHIFT_AMOUNT
      ]
      if op == ">":
        return obj1 > obj2
      elif op == "<":
        return obj1 < obj2
      elif op == "==":
        return obj1 == obj2
      elif op == "!=":
        return obj1 != obj2
      elif op == "<=":
        return obj1 <= obj2
      elif op == ">=":
        return obj1 >= obj2
      else:
        raise ValueError(f"Unsupported op: {op}")

    self.mock_trace_cmp.side_effect = mock_trace_cmp_side_effect

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

    original_code = simple_function.__code__
    patched_code = instrument_bytecode.patch_code(
        original_code, trace_dataflow=True
    )

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
      if 5 < a:
        return True
      return False

    original_code = const_compare.__code__
    patched_code = instrument_bytecode.patch_code(
        original_code, trace_control_flow=False, trace_dataflow=True
    )
    patched_function = types.FunctionType(patched_code, globals())

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

    @instrument_bytecode.instrument_func
    def to_be_instrumented(a, b):
      if a > b:
        return a
      return b

    self.assertIn("__ATHERIS_INSTRUMENTED__", to_be_instrumented.__code__.co_consts)

    self.assertEqual(to_be_instrumented(5, 3), 5)
    self.mock_trace_cmp.assert_called()
    self.mock_trace_branch.assert_called()

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

    with self.subTest("if branch"):
      self.assertEqual(patched_function(1), 10)
      self.mock_trace_cmp.assert_called()
      self.mock_trace_branch.assert_called()
      self.mock_trace_cmp.reset_mock()
      self.mock_trace_branch.reset_mock()

    with self.subTest("elif branch"):
      self.assertEqual(patched_function(2), 20)
      self.mock_trace_cmp.assert_called()
      self.mock_trace_branch.assert_called()
      self.mock_trace_cmp.reset_mock()
      self.mock_trace_branch.reset_mock()

    with self.subTest("else branch"):
      self.assertEqual(patched_function(3), 30)
      self.mock_trace_cmp.assert_called()
      self.mock_trace_branch.assert_called()

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

    with self.subTest("empty list"):
      self.assertEqual(patched_function([]), [])
      self.mock_trace_branch.assert_called()
      self.mock_trace_branch.reset_mock()

    with self.subTest("non-empty list"):
      self.assertEqual(patched_function([1, 2, 3]), [1, 2, 3])
      self.mock_trace_branch.assert_called()

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

    with self.subTest("zero iterations"):
      self.assertEqual(patched_function(0), 0)
      self.mock_trace_cmp.assert_called()
      self.mock_trace_branch.assert_called()
      self.mock_trace_cmp.reset_mock()
      self.mock_trace_branch.reset_mock()

    with self.subTest("multiple iterations"):
      self.assertEqual(patched_function(3), 3)
      self.mock_trace_cmp.assert_called()
      self.mock_trace_branch.assert_called()

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
    patched_code = instrument_bytecode.patch_code(
        original_code, trace_dataflow=True
    )
    patched_function = types.FunctionType(patched_code, globals())

    self.mock_trace_branch.reset_mock()
    self.assertEqual(patched_function(1, 2), 2)
    self.assertEqual(self.mock_trace_branch.call_count, 2)
    first_args = list(self.mock_trace_branch.call_args_list)

    self.mock_trace_branch.reset_mock()
    self.assertEqual(patched_function(3, 1), 3)
    self.assertEqual(self.mock_trace_branch.call_count, 2)
    second_args = list(self.mock_trace_branch.call_args_list)

    # Assert that we detected different branches being taken
    self.assertEqual(first_args[0], second_args[0])
    self.assertNotEqual(first_args[1], second_args[1])

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
      except:  # pylint: disable=bare-except
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


class InstrumentationTest(unittest.TestCase):
  """Tests that do not use mock, calling the real atheris instrumentation."""

  def test_instrument_all(self):
    """Import every module in the stdlib and instrument them all."""

    for module in sys.stdlib_module_names:
      if module == "antigravity":
        # this module opens an interactive console when imported.
        continue
      try:
        importlib.import_module(module)
      except (ImportError, ModuleNotFoundError):
        # Some modules might not be available or raise errors on import.
        pass
    instrument_bytecode.instrument_all()


if __name__ == "__main__":
  unittest.main()
