// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2020 Avast Software
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * @file
 * @brief Information gathering from Rizin and user.
 */

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#include <rapidjson/document.h>

#include <retdec/utils/io/log.h>

#include "rz-plugin/data.h"
#include "rz-plugin/utils.h"

using namespace retdec::common;
using namespace retdec::config;
using namespace retdec::rzplugin;
using fu = retdec::rzplugin::FormatUtils;
using retdec::utils::io::Log;

namespace {

const char* declarationInputVariable = "DEC_OBJECT_DECLARATIONS";

unsigned countPointerLevels(const std::string& spelling)
{
	return static_cast<unsigned>(std::count(spelling.begin(), spelling.end(), '*'));
}

bool spellingCarriesQualifier(const std::string& spelling)
{
	for (const char* token : {"volatile", "const", "restrict"})
	{
		if (spelling.find(token) != std::string::npos)
		{
			return true;
		}
	}
	return false;
}

bool spellingIsBaseAndPointers(const std::string& spelling)
{
	std::string base = spelling.substr(0, spelling.find('*'));
	std::string rest = spelling;
	rest.erase(std::remove(rest.begin(), rest.end(), '*'), rest.end());
	auto notSpace = [](char c) { return c != ' ' && c != '\t'; };
	base.erase(base.begin(), std::find_if(base.begin(), base.end(), notSpace));
	base.erase(std::find_if(base.rbegin(), base.rend(), notSpace).base(), base.end());
	rest.erase(rest.begin(), std::find_if(rest.begin(), rest.end(), notSpace));
	rest.erase(std::find_if(rest.rbegin(), rest.rend(), notSpace).base(), rest.end());
	return base == rest;
}

bool parseScalarLlvmType(const std::string& llvmIr, unsigned& width, unsigned& levels)
{
	std::string text = llvmIr;
	text.erase(std::remove_if(text.begin(), text.end(), [](char c) {
		return c == ' ' || c == '\t'; }), text.end());

	levels = 0;
	while (!text.empty() && text.back() == '*')
	{
		++levels;
		text.pop_back();
	}
	if (levels > 1 || text.size() < 2 || text[0] != 'i')
	{
		return false;
	}
	const std::string digits = text.substr(1);
	if (!std::all_of(digits.begin(), digits.end(), [](char c) {
			return c >= '0' && c <= '9'; }))
	{
		return false;
	}
	width = static_cast<unsigned>(std::strtoul(digits.c_str(), nullptr, 10));
	return width >= 8 && width <= 64;
}

bool validateDeclaredObject(const Object& object, int addressBits, std::string& reason)
{
	if (object.getName().empty())
	{
		reason = "empty name";
		return false;
	}
	const Address address = object.getStorage().getAddress();
	if (!object.getStorage().isMemory() || address.isUndefined() || address.getValue() == 0)
	{
		reason = "storage is not a defined global address";
		return false;
	}
	if (addressBits > 0 && addressBits < 64 && (address.getValue() >> addressBits) != 0)
	{
		reason = "address " + address.toHexPrefixString() + " does not fit the target's "
				+ std::to_string(addressBits) + "-bit address space";
		return false;
	}
	const Type& type = object.type;
	if (!type.isDefined())
	{
		reason = "missing LLVM type";
		return false;
	}
	if (!type.isVolatile())
	{
		reason = "missing object-level qualification";
		return false;
	}
	const std::string& spelling = type.getCType();
	if (spelling.empty())
	{
		reason = "missing C base type";
		return false;
	}
	if (spellingCarriesQualifier(spelling))
	{
		reason = "qualifier inside the spelling would qualify the pointee: \"" + spelling + "\"";
		return false;
	}
	if (!spellingIsBaseAndPointers(spelling))
	{
		reason = "spelling is not a base type followed by pointer levels: \"" + spelling + "\"";
		return false;
	}
	unsigned width = 0;
	unsigned levels = 0;
	if (!parseScalarLlvmType(type.getLlvmIr(), width, levels))
	{
		reason = "unsupported LLVM type: \"" + type.getLlvmIr() + "\"";
		return false;
	}
	const unsigned baseWidth = type.getCBaseTypeWidth();
	if (baseWidth == 0)
	{
		reason = "unsupported base type: \"" + spelling + "\"";
		return false;
	}
	if (baseWidth != width)
	{
		reason = "base type width " + std::to_string(baseWidth)
				+ " disagrees with the LLVM type \"" + type.getLlvmIr() + "\"";
		return false;
	}
	if (countPointerLevels(spelling) != levels)
	{
		reason = "pointer levels in \"" + spelling + "\" disagree with the LLVM type \""
				+ type.getLlvmIr() + "\"";
		return false;
	}
	return true;
}

void mergeDeclaredObjects(
		Config& config,
		const Config& supplied,
		const std::string& path,
		int addressBits)
{
	std::vector<std::string> rejected;
	std::vector<const Object*> accepted;
	std::map<std::string, Address> names;
	std::map<Address, std::string> addresses;

	for (const auto& object : supplied.globals)
	{
		const std::string label = object.getName().empty() ? std::string("<unnamed>") : object.getName();
		std::string reason;
		if (!validateDeclaredObject(object, addressBits, reason))
		{
			rejected.push_back(label + ": " + reason);
			continue;
		}

		const Address address = object.getStorage().getAddress();
		const Object* byName = config.globals.getObjectByName(object.getName());
		const Object* byAddress = config.globals.getObjectByAddress(address);
		const auto namedAt = names.find(object.getName());
		const auto addressedAs = addresses.find(address);
		if (byName && byName->getStorage().getAddress() != address)
		{
			rejected.push_back(label + ": name already declared at "
					+ byName->getStorage().getAddress().toHexString());
			continue;
		}
		if (byAddress && byAddress->getName() != object.getName())
		{
			rejected.push_back(label + ": address already declared as \""
					+ byAddress->getName() + "\"");
			continue;
		}
		if (namedAt != names.end() && namedAt->second != address)
		{
			rejected.push_back(label + ": declared twice with different addresses");
			continue;
		}
		if (addressedAs != addresses.end() && addressedAs->second != object.getName())
		{
			rejected.push_back(label + ": address declared as \""
					+ addressedAs->second + "\" as well");
			continue;
		}

		names[object.getName()] = address;
		addresses[address] = object.getName();
		accepted.push_back(&object);
	}

	if (!rejected.empty())
	{
		Log::error() << declarationInputVariable << ": rejected \"" << path << "\": "
				<< rejected.size() << " invalid declaration(s); none applied" << std::endl;
		for (const auto& item : rejected)
		{
			Log::error() << "  " << item << std::endl;
		}
		return;
	}

	for (const Object* object : accepted)
	{
		config.globals.insert(*object);
	}
	Log::info() << declarationInputVariable << ": applied " << accepted.size()
			<< " declaration(s) from \"" << path << "\"" << std::endl;
}

bool documentRepresents(const std::string& text, std::size_t represented, std::string& reason)
{
	rapidjson::Document document;
	document.Parse(text.c_str());
	if (document.HasParseError())
	{
		reason = "is not valid JSON";
		return false;
	}
	if (!document.IsObject() || !document.HasMember("globals"))
	{
		return true;
	}
	const auto& globals = document["globals"];
	if (!globals.IsArray())
	{
		reason = "\"globals\" is not an array";
		return false;
	}
	if (globals.Size() != represented)
	{
		reason = "declares " + std::to_string(globals.Size()) + " global(s), but only "
				+ std::to_string(represented) + " represent a distinct global object";
		return false;
	}
	return true;
}

void applyDeclaredObjects(Config& config, int addressBits)
{
	const char* path = std::getenv(declarationInputVariable);
	if (path == nullptr || *path == '\0')
	{
		return;
	}
	try
	{
		std::ifstream stream(path);
		if (!stream)
		{
			throw std::runtime_error("cannot be opened");
		}
		const std::string text((std::istreambuf_iterator<char>(stream)),
				std::istreambuf_iterator<char>());
		const Config supplied = Config::fromJsonString(text);
		std::string reason;
		if (!documentRepresents(text, supplied.globals.size(), reason))
		{
			Log::error() << declarationInputVariable << ": rejected \"" << path << "\": "
					<< reason << std::endl;
			return;
		}
		mergeDeclaredObjects(config, supplied, path, addressBits);
	}
	catch (const std::exception& error)
	{
		Log::error() << declarationInputVariable << ": rejected \"" << path << "\": "
				<< error.what() << std::endl;
	}
}

}

/**
 * Translation map between tokens representing calling convention type returned
 * by Rizin and CallingConventionID that is recognized by RetDec.
 */
std::map<const std::string, const CallingConventionID> RizinDatabase::_rzrdcc = {
	{"arm32", CallingConventionID::CC_ARM},
	{"arm64", CallingConventionID::CC_ARM64},

	{"n32", CallingConventionID::CC_MIPS},

	{"powerpc-32", CallingConventionID::CC_POWERPC},
	{"powerpc-64", CallingConventionID::CC_POWERPC64},

	{"amd64", CallingConventionID::CC_X64},
	{"ms", CallingConventionID::CC_X64},

	{"borland", CallingConventionID::CC_PASCAL},
	{"cdecl", CallingConventionID::CC_CDECL},
	{"cdecl-thiscall-ms", CallingConventionID::CC_THISCALL},
	{"fastcall", CallingConventionID::CC_FASTCALL},
	{"pascal", CallingConventionID::CC_PASCAL},
	{"stdcall", CallingConventionID::CC_STDCALL},
	{"watcom", CallingConventionID::CC_WATCOM}
};

RizinDatabase::RizinDatabase(RzCore &core):
	_rzcore(core)
{
}

/**
 * @brief Fetches path of the binary file from Rizin.
 */
std::string RizinDatabase::fetchFilePath() const
{
	if (rz_pvector_empty(&_rzcore.file->binfiles)) {
		return std::string();
	}
	RzBinFile *bf = reinterpret_cast<RzBinFile *>(rz_pvector_at(&_rzcore.file->binfiles, 0));
	return bf->file ? std::string(bf->file) : "";
}

void RizinDatabase::setFunction(const common::Function &fnc) const
{
	auto rzfnc = rz_analysis_get_function_at(_rzcore.analysis, fnc.getStart().getValue());
	if (rzfnc == nullptr) {
		rzfnc = rz_analysis_create_function(_rzcore.analysis, fnc.getName().c_str(),
				fnc.getStart().getValue(), RZ_ANALYSIS_FCN_TYPE_FCN);
		if (rzfnc == nullptr) {
			throw DecompilationError("Unable to create function on address "
					+ std::to_string(fnc.getStart().getValue()));
		}
	}

	if (!fnc.isDynamicallyLinked() && fnc.getSize().getValue() > 1)
		if (!rz_analysis_fcn_add_bb(_rzcore.analysis, rzfnc, fnc.getStart().getValue(), fnc.getSize().getValue(), UT64_MAX, UT64_MAX))
			Log::error() << Log::Warning << "unable to add basic block of " << fnc.getName() << std::endl;

	copyFunctionData(fnc, *rzfnc);
}

std::string sanitize(const std::string& a)
{
	std::ostringstream ok;
	for (auto& c: a)
		if (c != '$' && c != '@' && c != '.')
			ok << c;

	return ok.str();
}

void RizinDatabase::copyFunctionData(const common::Function &fnc, RzAnalysisFunction &rzfnc) const
{
	if (rz_analysis_function_rename(&rzfnc, fnc.getName().c_str()) == false) {
		std::ostringstream err;
		err << "unable to set rename function at offset "
			<< std::hex << fnc.getStart() << ": new name \"" << fnc.getName();
		throw DecompilationError(err.str());
	}

	// TODO: Disabled as rz_analysis_str_to_fcn does not exist anymore
#if 0
	// TODO:
	//   - Provide "hack":
	//     Get/Create declaration string. When such string is available provide "sanitization".
	//     Sanitization will check for symbols that r2 cannot parse and replace them with
	//     more appropriate symbols.
	if (false && !fnc.getDeclarationString().empty()) {
		rz_analysis_str_to_fcn(_rzcore.analysis, &rzfnc, (fnc.getDeclarationString()+";").c_str());
	}
	else {
		std::ostringstream data;
		data << fu::convertLlvmTypeToC(fnc.returnType.getLlvmIr()) << " "
			<< fnc.getName() << "(";

		if (!fnc.parameters.empty()) {
			data << fu::convertLlvmTypeToC(fnc.parameters.front().type.getLlvmIr());
			data << " " << fnc.parameters.front().getName();
		}
		for (auto& a: fnc.parameters) {
			data << ", " << fu::convertLlvmTypeToC(a.type.getLlvmIr())
				<< " " << a.getName();
		}
		data << ");";
		rz_analysis_str_to_fcn(_rzcore.analysis, &rzfnc, sanitize(data.str()).c_str());
	}
#endif
}

void RizinDatabase::setFunctions(const config::Config& config) const
{
	for (auto& fnc: config.functions) {
		setFunction(fnc);
	}
}

/**
 * @brief Fetches the function at the address passed as parameter.
 *
 * @param addr Analyzes the function at the given address.
 */
Function RizinDatabase::fetchFunction(ut64 addr) const
{
	RzAnalysisFunction *cf = rz_analysis_get_fcn_in(_rzcore.analysis, addr, RZ_ANALYSIS_FCN_TYPE_NULL);
	if (cf == nullptr) {
		std::ostringstream errMsg;
		errMsg << "no function at offset 0x" << std::hex << addr;
		throw DecompilationError(errMsg.str());
	}

	return convertFunctionObject(*cf);
}

Function RizinDatabase::fetchSeekedFunction() const
{
	return fetchFunction(_rzcore.offset);
}

/**
 * @brief Fetches functions and global variables from Rizin.
 */
void RizinDatabase::fetchFunctionsAndGlobals(Config &rzconfig) const
{
	auto list = rz_analysis_function_list(_rzcore.analysis);
	if (list != nullptr) {
		FunctionContainer functions;
		for (RzListIter *it = list->head; it; it = rz_list_next(it)) {
			auto fnc = reinterpret_cast<RzAnalysisFunction*>(rz_list_val(it));
			if (fnc == nullptr)
				continue;
			functions.insert(convertFunctionObject(*fnc));
		}

		rzconfig.functions = functions;
	}
	fetchGlobals(rzconfig);
}

/**
 * @brief Fetches global variables from the Rizin.
 *
 * This method is intended only for internal usage. That is
 * why this method is private. To obtain functions and global
 * variables the RizinDatabase::fetchFunctionsAndGlobals
 * method is available.
 *
 * While browsing flags and symbols this method provides correction
 * of fetched functions as some of them might be dynamically linked.
 * This is another reason why this method is private and interface
 * to fetch globals is integrated with interface to fetch functions.
 */
void RizinDatabase::fetchGlobals(Config &config) const
{
	RzBinObject *obj = rz_bin_cur_object(_rzcore.bin);
	auto list = rz_analysis_var_global_get_all(_rzcore.analysis);

	GlobalVarContainer globals;
	FunctionContainer functions;

	void **it;
	if (obj && obj->symbols) rz_pvector_foreach(obj->symbols, it) {
		auto sym = reinterpret_cast<RzBinSymbol*>(*it);
		if (sym == nullptr)
			continue;

		std::string type(sym->type);
		std::string name(sym->name);
		std::string bind(sym->bind);
		bool isImported = sym->is_imported;

		// If type is FUNC and flag is set to true
		// the function should be checked wheter it
		// was not fetched and should be corrected.
		//
		// In future this code should be moved to the fetch
		// functions method. As this function is private
		// and this is the intended usage for now I decided
		// to let it here.
		if (type == "FUNC" && isImported) {
			auto it = config.functions.find(name);
			if (it != config.functions.end()) {
				Function f = *it;
				f.setIsVariadic(true);
				f.setIsDynamicallyLinked();
				functions.insert(f);
			}
			else {
				//TODO: do we want to include these functions?
			}
		}
	}

	// Searching through all globals
	for (RzListIter *it = list ? list->head : nullptr; it; it = rz_list_next(it)) {
			auto glob = reinterpret_cast<RzAnalysisVarGlobal*>(rz_list_val(it));
			if (glob == nullptr)
				continue;

			Object var(glob->name, Storage::inMemory(glob->addr));
			var.setRealName(glob->name);
			var.setIsFromDebug(true);
			if (glob->type) {
				auto typedb = rz_analysis_get_type_db(_rzcore.analysis);
				var.type = Type(fu::convertTypeToLlvm(typedb, glob->type));
				if (char *spelling = rz_type_as_string(typedb, glob->type)) {
					var.type.setCType(spelling);
					rz_mem_free(spelling);
				}
			}
			globals.insert(var);
	}
	rz_list_free(list);

	// If we found at least one dynamically linked function.
	if (!functions.empty()) {
		for (auto f: config.functions) {
			functions.insert(f);
		}
		config.functions = std::move(functions);
	}

	config.globals = globals;

	applyDeclaredObjects(config, rz_analysis_get_bits(_rzcore.analysis));
}

/**
 * Converts function object from its representation in Rizin into
 * represnetation that is used in RetDec.
 */
Function RizinDatabase::convertFunctionObject(RzAnalysisFunction &rzfnc) const
{
	auto start = rz_analysis_function_min_addr(&rzfnc);
	auto end = rz_analysis_function_max_addr(&rzfnc);

	auto name = fu::stripName(rzfnc.name);

	Function function(start, end, name);

	function.setIsUserDefined();
	fetchFunctionReturnType(function, rzfnc);
	fetchFunctionCallingconvention(function, rzfnc);
	fetchFunctionLocalsAndArgs(function, rzfnc);

	return function;
}

/**
 * Fetches local variables and arguments of a functon.
 *
 * As there are more types of storage of arguments they can be fetched from multiple sources
 * in radare2. this is the reason why there is only one interface for fetching arguments and
 * local variables.
 *
 * When user do not provide argument for a function and the function has calling convention
 * that does not use registers (cdecl), the aruments are are deducted in rizin based on the offset.
 * This is not, however, projected into function's calling convention and the args are needed to
 * be fetched with stack variables of the funciton.
 */
void RizinDatabase::fetchFunctionLocalsAndArgs(Function &function, RzAnalysisFunction &rzfnc) const
{
	ObjectSetContainer locals;
	ObjectSequentialContainer rzargs, rzuserArgs;

	void **it;
	rz_pvector_foreach(&rzfnc.vars, it) {
		auto locvar = reinterpret_cast<RzAnalysisVar *>(*it);
		if (locvar == nullptr)
			continue;

		Storage variableStorage;
		switch (locvar->storage.type) {
		case RZ_ANALYSIS_VAR_STORAGE_REG:
			variableStorage = Storage::inRegister(locvar->storage.reg);
			break;
		case RZ_ANALYSIS_VAR_STORAGE_STACK: {
			int stackOffset = locvar->storage.stack_off;
			if (stackOffset > 0) {
				// When below the stack frame (args), subtract the size of the
				// return address to match retdec's address handling there.
				stackOffset -= fetchWordSize() / 8;
			}
			variableStorage = Storage::onStack(stackOffset);
		}
		break;
		default:
			continue;
		};

		Object var(locvar->name, variableStorage);
		var.type = Type(fu::convertTypeToLlvm(rz_analysis_get_type_db(_rzcore.analysis), locvar->type));
		var.setRealName(locvar->name);

		// If variable is argument it is a local variable too.
		if (rz_analysis_var_is_arg(locvar))
			rzargs.push_back(var);

		locals.insert(var);
	}

	fetchExtraArgsData(rzuserArgs, rzfnc);

	function.locals = locals;

	// User specified arguments must have higher priority
	function.parameters = rzuserArgs.empty() ? rzargs : rzuserArgs;
}

/**
 * @brief Fetches function arguments defined by user.
 */
void RizinDatabase::fetchExtraArgsData(ObjectSequentialContainer &args, RzAnalysisFunction &rzfnc) const
{
	RzAnalysisFuncArg *arg;

	char* key = rz_analysis_function_name_resolve(_rzcore.analysis, rzfnc.name);
	auto typedb = rz_analysis_get_type_db(_rzcore.analysis);
	if (!key || !_rzcore.analysis || !typedb)
		return;

	int nargs = rz_type_func_args_count(typedb, key);
	if (nargs) {
		RzList *list = rz_core_get_func_args(&_rzcore, rzfnc.name);
		for (RzListIter *it = list->head; it; it = rz_list_next(it)) {
			arg = reinterpret_cast<RzAnalysisFuncArg*>(rz_list_val(it));
			Object var(arg->name, Storage::undefined());
			var.setRealName(arg->name);
			var.type = Type(fu::convertTypeToLlvm(typedb, arg->orig_c_type));
			if (char *spelling = rz_type_as_string(typedb, arg->orig_c_type)) {
				var.type.setCType(spelling);
				rz_mem_free(spelling);
			}
			args.push_back(var);
		}
		rz_list_free (list);
	}
	rz_mem_free(key);
}

/**
 * @brief Fetches the calling convention of the input function from Rizin.
 */
void RizinDatabase::fetchFunctionCallingconvention(Function &function, RzAnalysisFunction &rzfnc) const
{
	if (rzfnc.cc != nullptr) {
		if (_rzrdcc.count(rzfnc.cc)) {
			function.callingConvention = _rzrdcc[rzfnc.cc];
			return;
		}
	}

	function.callingConvention = CallingConventionID::CC_UNKNOWN;
}

/**
 * @brief Fetches the return type of the input function from Rizin.
 */
void RizinDatabase::fetchFunctionReturnType(Function &function, RzAnalysisFunction &rzfnc) const
{
	function.returnType = Type("void");
	char* key = rz_analysis_function_name_resolve(_rzcore.analysis, rzfnc.name);
	auto typedb = rz_analysis_get_type_db(_rzcore.analysis);

	if (!key || !_rzcore.analysis || !typedb)
		return;

	if (auto returnType = rz_type_func_ret(typedb, key))
		function.returnType = Type(fu::convertTypeToLlvm(typedb, returnType));

	rz_mem_free(key);
}

/**
 * @brief Fetch word size of the input file architecture.
 */
size_t RizinDatabase::fetchWordSize() const
{
	return rz_config_get_i(_rzcore.config, "asm.bits");
}

ut64 RizinDatabase::seekedAddress() const
{
	return _rzcore.offset;
}

const RzCore& RizinDatabase::core() const
{
	return _rzcore;
}
