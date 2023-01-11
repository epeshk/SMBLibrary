About SMBLibrary.Async:
=================
SMBLibrary.Async is an open-source C# SMB 2.0, SMB 2.1 and SMB 3.0 client implementation. Not all SMB features are implemented.

SMBLibrary.Async is a fork of the [SMBLibrary](https://github.com/TalAloni/SMBLibrary) with reduced functionality, but also with truly asynchronous API and low memory traffic.

The sole purpose of this fork is to improve performance over the original library. No additional features have been implemented.

Differences from the original library:
========
- Server code removed
- SMB 1 support removed
- All SMB2Client operations are asynchronous
- Read/Write operations allocate less memory
- Other small memory traffic optimizations
- Improved signing and encryption performance

Using SMBLibrary.Async:
=================
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Licensing:
==========
SMBLibrary.Async released under the LGPL 3.0 license. All uses of this fork must comply with the LGPL 3.0 license, and any non-LGPL 3.0 compatible licenses aren't applicable.

Contact:
========
If you have any question or suggestion, feel free to open an issue or pull request. But there is no warranty that your issue will be resolved or pull request will be accepted. However, improvements are always welcome!

SMBLibrary.Async only supports modern versions of dotnet.
