# Working with global data

Globally defined data is the second most important thing a reverse-engineer can find in a binary (the first
most important is of course the code itself). That's why Ghidralib includes many helpful utilities
to work with it. Most important Ghidralib wrappers used to work with global data are:

* [Data](reference.md#ghidralib.Data) - represents a fragment of binary that is used to store a piece of data. Wraps `ghidra.program.model.listing.Data`.
* [DataType](reference.md#ghidralib.DataType) - all data objects have an assigned type, that determines many things, including the way it's displayed, decompiled and more. Wraps `ghidra.program.model.data.DataType`.


### Defining data

When one runs auto-analysis, large chunks of the program are automatically analysed and marked as code
or data. But sometimes, during analysis, we discover a new piece of data that was not previously
defined. We may want to automate adding it. Ghidra's FlatProgramAPI is pretty good here - we
have a lot of functions like `createByte`, `createChar`, `createDouble`, `createDWord`, etc.

But one very annoying problem with them is that they raise an exception when a data is already defined there.
For example, given:

```asm
00457994 34 32           dw         3234h
```

When we attempt to:

```python
createByte(toAddr(0x0457994))  # remember that you need toAddr here
```

We'll get a long exception about conflicting data types. With Ghidralib we can do it
a bit more safely by leveraging `Program.create_data`:

```python
data = Program.create_data(0x0457994, "byte")
```

Or alternatively, using a DataType object:

```python
data = DataType("byte").create_at(0x0457994)
```

As usual, we can also access the existing defined data:

```python
data = Data(0x0457994)  # Get by address
data = Data("DAT_00457994")  # Get by name, if exists
```

With a `Data` instance we can easily access a lot of information, but most importantly we can:

* Access it's address, size, raw bytes, etc

```python
>>> Data(0x0400078).address
4194424L
>>> Data(0x0400078).length
248
```

As a fun exercise, like with everything that occupies bytes in the binary address space, we
can also highlight it in the listing:

```python
Data(0x0400078).highlight()s
```

* Get its type with `data_type` or `base_data_type`.

```python
>>> Data(0x0457994).data_type
word
```

* Introspect it, for example `is_pointer`, `is_constant`, `is_writable`, `is_array`, `is_structure`, etc.

```python
>>> Data(0x0400078).is_pointer
False
>>> Data(0x0400078).is_writable
False
```

* For primitive types, cast it to a Python type (when it makes sense):

```python
>>> Data(0x0457994).value
0x3234
```

* For structures, access the nested fields with no boilerplate:

```python
>>> Data(0x0400000).e_magic
char[2] "MZ"
>>> Data(0x0400000).e_magic.value
'MZ'
>>> Data(0x400078).OptionalHeader.DataDirectory[1].Size
ddw 8Ch
```

### Data types

Every `Data` object has a type assigned. Types are represented by a
[DataType](reference.md#ghidralib.DataType) object. It can be used to query information about how
that data behaves.

It's possible to get the type by name, or to enumarate all data types:

```python
>>> len(DataType.all())
110528
>>> DataType("IMAGE_OPTIONAL_HEADER32")
/PE/IMAGE_OPTIONAL_HEADER32
pack(disabled)
Structure IMAGE_OPTIONAL_HEADER32 {
   0   word   2   Magic   ""
   2   byte   1   MajorLinkerVersion   ""
   3   byte   1   MinorLinkerVersion   ""
...
```

Currently Ghidralib has a limited support for data type introspetion - it's
possible to get the type name, size in bytes, and not much more. For more advanced operations,
it may be necessary to use the raw Java object directly. For example:

```python
>>> DataType("IMAGE_OPTIONAL_HEADER32").raw.getPathName()
u'/PE/IMAGE_OPTIONAL_HEADER32'
>>> DataType("IMAGE_OPTIONAL_HEADER32").raw.getDescription()
u''
>>> DataType("IMAGE_OPTIONAL_HEADER32").raw.getAlignment()
1
```

As usual, in the future missing wrappers may be added.

One interesting feature is C code parsing, for example:

```python
>>> DataType.from_c('typedef void* HINTERNET;')
HINTERNET
>>> DataType.from_c("struct test { short a; short b; short c;};")
pack()
Structure test {
0   short   2   a   ""
2   short   2   b   ""
4   short   2   c   ""
}
Length: 6 Alignment: 2
```

Adding a data type programatically is sometimes much easier than doing it manually in the structure editor.

