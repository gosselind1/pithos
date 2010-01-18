/*
Copyright (c) 2008-2009
	Lars-Dominik Braun <PromyLOPh@lavabit.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

/* encryption key for xmlrpc */

#ifndef _CRYPT_KEY_OUTPUT_H
#define _CRYPT_KEY_OUTPUT_H

#include <stdint.h>

const unsigned int out_key_n = 16;

static const uint32_t out_key_p [16 + 2] = {
		0xC10590ECL, 0xBA979EE1L, 0x04EEE520L, 0x759C8C59L,
		0x22804BA7L, 0x7C46EB7AL, 0x21ACF684L, 0xB9A7B8E7L,
		0xBEED610AL, 0xDB325139L, 0xDF84AD90L, 0x31FB85C8L,
		0xA5468088L, 0x7241BC17L, 0xD6E88A88L, 0xA375F4A4L,
		0x223BF5EFL, 0xEDA2CDB5L,
		};

static const uint32_t out_key_s [4][256] = {{
		0x9654C859L, 0x909BC929L, 0x6C13EA8EL, 0xFB78C4F8L,
		0xA1DD8C99L, 0x9C04168AL, 0x2A43D4A9L, 0x52BE439BL,
		0x10040365L, 0x422C267DL, 0x5210312EL, 0x0AD6D8ECL,
		0x14814E6FL, 0xAB8A7E9FL, 0x981A1DBAL, 0x6C7EC03DL,
		0xA4DBEB04L, 0x1BEC8694L, 0x30FDF157L, 0x5C903DD3L,
		0xFEC8D421L, 0x32949BEEL, 0x089C0351L, 0x0F678350L,
		0xD71DEB51L, 0x3DC9F297L, 0xD0AD6F45L, 0x0909CB0EL,
		0x37EE1700L, 0xF1522308L, 0x7A117A9AL, 0x21606DDEL,
		0x0F69ED07L, 0x1D2A8FE0L, 0xEF95F5ADL, 0xA1F8C13CL,
		0x10480D0DL, 0x2B1914BEL, 0x19071638L, 0xC75AF34FL,
		0x65CABBB2L, 0x4CA28F5EL, 0xA6264839L, 0x7623BEA7L,
		0x24DFBDA6L, 0x7CFC1117L, 0xDF916C8FL, 0x6ABF9E8FL,
		0x2C9E8F85L, 0x03B9ECF6L, 0x39CFFD8FL, 0x302A0460L,
		0xE28543C0L, 0x37EA897BL, 0x36E025E3L, 0xD4620943L,
		0x4F5CA829L, 0x8F33310FL, 0x730F4503L, 0x8052DB67L,
		0x2E0B8A1DL, 0x91195FFBL, 0x2A49B357L, 0x3578D2ECL,
		0x8F2BC8CEL, 0x197D2ED1L, 0xBB5B1B11L, 0x3B02F424L,
		0x8DE5D13AL, 0x2F4C7F70L, 0xE66AB0CFL, 0xDF93C57BL,
		0x48B52549L, 0x735CB3FCL, 0x6FA34C40L, 0xEABD8238L,
		0xD5FB57D5L, 0xB574BEFAL, 0x7AF7D0E9L, 0x30D82D91L,
		0x3DC52795L, 0x9A66F1C5L, 0x1014D6D7L, 0x1619B896L,
		0xA465E2D6L, 0x0DEF33EDL, 0x213BB77DL, 0x65B1A904L,
		0x964751B0L, 0x5335C857L, 0xF72060E0L, 0x579458DBL,
		0xA33556FEL, 0x8D41DD66L, 0x7165D4F8L, 0x261D183EL,
		0xD55FF261L, 0xBFC3852BL, 0xEB4050C3L, 0xF500FC86L,
		0x19E25B41L, 0x5A366B1AL, 0xDEBCB9ACL, 0xF3E2D6D0L,
		0x4DE3EE3AL, 0x2579418DL, 0xE94C1BC9L, 0x39ABD007L,
		0xEEBF9405L, 0x3E091753L, 0x8757A7E7L, 0x66456984L,
		0xE1AD1E6BL, 0x0C76A1B8L, 0xDFBFA09EL, 0x67431807L,
		0x9B8E1496L, 0x038FDE39L, 0xA9656FF5L, 0x48A6C2F9L,
		0x2A531F33L, 0xE6213074L, 0xE1E98733L, 0x42BECE69L,
		0xD1F77AD7L, 0xC8EE6C6CL, 0x221F337FL, 0x37D93CE7L,
		0x94E6954FL, 0x98557669L, 0xB78ADEA9L, 0xC97DB869L,
		0x99BB9FF9L, 0x7B245A04L, 0xB56E2F44L, 0x6DE4945EL,
		0xD5C550E9L, 0xE2406878L, 0x9178BEC4L, 0xA1CEEF70L,
		0x6A543D9BL, 0x5DF98E33L, 0x1801A7B3L, 0x1E9B8C86L,
		0x5501FBE1L, 0xC7E53071L, 0x94855AD1L, 0x550E1997L,
		0x260C8E5AL, 0xA40F1E26L, 0x55CDE2B4L, 0x55C7850CL,
		0x5A6FC9D3L, 0x8ED207BFL, 0x3BA77DFEL, 0x2505DED6L,
		0x0CF49779L, 0x57F557C6L, 0x59474010L, 0x638BA8A2L,
		0x4D82F6EBL, 0x677D6829L, 0x44C2CFC1L, 0xD2C006A7L,
		0x21D5BE8EL, 0x5D8442D1L, 0x6174F23FL, 0xE2AA0EF3L,
		0x54328E77L, 0x046A7983L, 0x6523470BL, 0x2CCCDB19L,
		0x6683ABA1L, 0x191B22A4L, 0x53131029L, 0x1BE73145L,
		0x27C1F557L, 0xA819BDA8L, 0x3E47B139L, 0xBE3C46ACL,
		0x42C59203L, 0x92C6FD74L, 0x491AA43AL, 0x1AD367C3L,
		0x628A99C8L, 0x3051E88EL, 0x67C54A0DL, 0xAA278070L,
		0x35776A31L, 0x97557DE3L, 0x4B84E68FL, 0x187A039FL,
		0xFD0DB4BCL, 0x0F4C4286L, 0xBA4F54FCL, 0xCBBC90C3L,
		0x0F269800L, 0xB78EC21BL, 0x1C97FE3AL, 0xA808792CL,
		0x7B658426L, 0x81590C6CL, 0xC7890561L, 0x8A07080EL,
		0x9D99E5E4L, 0xC3929BC4L, 0x31E5D06AL, 0x97A82A07L,
		0xC7A53A0EL, 0x68596FAFL, 0x02F8D609L, 0x14E256EBL,
		0xFFE202E1L, 0xFB13E18FL, 0x21B1DB15L, 0x354080D6L,
		0x777FED00L, 0xE6C89DC5L, 0x711A18F6L, 0x40C8E33BL,
		0x709E7E2DL, 0x359C6507L, 0x56CB9F2CL, 0x92B8A949L,
		0x87E360F2L, 0xC19CCB2EL, 0x623B905CL, 0x019F36D0L,
		0x7AE0EC6BL, 0x2C903F89L, 0xDB621170L, 0x2EF6B8C6L,
		0x6656BA25L, 0xF915180CL, 0xCDEE1BD7L, 0x85E38EDBL,
		0x7A9AC026L, 0xCA917632L, 0xFCFDDC64L, 0x5C3A7D51L,
		0x71DA7223L, 0xA8D48E72L, 0x2A3BA8E0L, 0x710919D3L,
		0xAB50A080L, 0xD6228237L, 0xB41B7A76L, 0xD82B39F5L,
		0x1E922C3FL, 0x6656D136L, 0x4A8473A7L, 0xA82AEE63L,
		0xDF451C42L, 0x62E2AE0EL, 0xECA484F3L, 0x1EBF64B5L,
		}, {
		0xF5CF4FEFL, 0xA6EAEDC5L, 0x3E59980DL, 0xC8F3911CL,
		0x9490F545L, 0x053579EBL, 0x5645E167L, 0x2015A54BL,
		0xEA2F52D0L, 0xBB28B315L, 0x1B907EF4L, 0x9C841317L,
		0xD03F498FL, 0x57045C47L, 0x992D554DL, 0x9D801A54L,
		0x1638D6B3L, 0x088C1854L, 0xA74D1549L, 0xFD2B5787L,
		0xFBE12709L, 0x0432BB66L, 0x880BCD01L, 0xB9065D9EL,
		0x1C2FB7B5L, 0xD27DA333L, 0x8A3D4436L, 0x7310F49EL,
		0x128BE54FL, 0x772B8A37L, 0x55579A3CL, 0xBC75F552L,
		0x38EB2E19L, 0x7C356617L, 0x1DE8D4C2L, 0xD0E43CDFL,
		0xD46044DDL, 0x252685EFL, 0x24051EE5L, 0x5B6BD82EL,
		0x495B6F47L, 0x39E52934L, 0x31B81CDDL, 0x001487D6L,
		0xC2B8B92BL, 0x8B8A0F1BL, 0xDB763075L, 0xE8FC685FL,
		0x9C3BD739L, 0x60E6A1FCL, 0xB628A9A6L, 0x0CD27CAAL,
		0x950A56F4L, 0x88691D4EL, 0xFCB51D66L, 0xDEB6D9B1L,
		0xB25625F6L, 0x75C1D492L, 0x36D4A98CL, 0x9C5AC60DL,
		0xF2AD970BL, 0x7E096239L, 0x6C5D1C4EL, 0x0440BEF8L,
		0x2855E769L, 0x35442FEBL, 0x525D6F15L, 0xA0D85345L,
		0x14AC130FL, 0x640B6DB5L, 0x15FF503EL, 0x7375B927L,
		0x48CE4829L, 0xEEDEF8E8L, 0x223AD535L, 0xFA97618CL,
		0xDA086CC5L, 0xA9020E63L, 0x89A828FFL, 0x757F0BFDL,
		0xEAD8E38FL, 0x0864E3F9L, 0xEFF82819L, 0xD7DE2BADL,
		0x2183D925L, 0x1C10EA2BL, 0xD4405FB2L, 0x24562242L,
		0xB56178F8L, 0xD1682BBFL, 0xCDE0FF93L, 0xB135F2C6L,
		0x6E95F144L, 0x215484A8L, 0xB335ADA4L, 0x0010752BL,
		0xE7126EB1L, 0x2F30AA95L, 0x73C04D5BL, 0xEBF14789L,
		0x5BE0FF05L, 0xB2C3129FL, 0x6D115378L, 0x8A0C4623L,
		0xE716AFEBL, 0x6B3F36C0L, 0x71D23F25L, 0xDEF919A5L,
		0x9B1CC604L, 0x4E708139L, 0x1D206BF9L, 0x8C9C2BE3L,
		0xAC43A8F3L, 0xCFB11067L, 0x0F741B5EL, 0x1EA6C0F3L,
		0x86D5CC7EL, 0x21189475L, 0x088E9460L, 0x6F91D8ABL,
		0x2D8C61C5L, 0x45360E78L, 0xE4A226D5L, 0x5C769AB6L,
		0x2B67A136L, 0x6F8ADF6FL, 0xADE04340L, 0x55FE66DBL,
		0xC334EF8AL, 0x61460C50L, 0x8DA1FF40L, 0x75824980L,
		0x721FEFC9L, 0x948C22BAL, 0x661E3C96L, 0xFC1CDEE7L,
		0x4C6C3ABEL, 0x67F1A2F5L, 0xE5EA0CCBL, 0xB58E9977L,
		0x13A78F94L, 0x32921073L, 0xA9BEE311L, 0x5B9D7CA1L,
		0x8681D048L, 0x43E439B2L, 0x4E80B689L, 0x6A9B1125L,
		0x268E3FABL, 0xF39E12F7L, 0xEEC77123L, 0xD7B98ADEL,
		0xB525DE74L, 0xD067F1D7L, 0x5B341ADEL, 0xC16E27BCL,
		0xB61BC08EL, 0x0E8A0856L, 0x8318DC09L, 0x9C02B9DBL,
		0xC6734B93L, 0x8C1CDB58L, 0xF729A76DL, 0x71288BC1L,
		0x7D4685D0L, 0x0CCA95F1L, 0xFCDB8B5DL, 0xDE1EB92BL,
		0xE6CC8BC2L, 0xC78D5B70L, 0xD73387E8L, 0x5676050AL,
		0x071D0C54L, 0x04ED3ED2L, 0x3FF4ECF5L, 0x971EF95DL,
		0x367D0085L, 0x633E3555L, 0x78A90717L, 0xD52D7BD6L,
		0x81F57041L, 0x3CCEF4AFL, 0x5A2ECFE9L, 0x19B81054L,
		0x837C3482L, 0x78DB4BCBL, 0xB7E7A2FCL, 0xEBC3AC19L,
		0x955ECEECL, 0x9AF50F17L, 0x04C62335L, 0x0D548A8CL,
		0x174D4064L, 0x5801584FL, 0x1C16E012L, 0xCD1742C1L,
		0x97A4E3B1L, 0x4DF37C91L, 0x4169A93AL, 0x9B726C3BL,
		0x886D38CFL, 0x01062DDFL, 0x045B14B7L, 0xF4A333B8L,
		0x64F0981BL, 0x17A139C8L, 0x660678F8L, 0x3268CEC7L,
		0xF60A6DACL, 0x98C455DFL, 0x493BFFA5L, 0x0927C471L,
		0x1523D52DL, 0x32ACA049L, 0x09D59F95L, 0x82B8D198L,
		0x66E92CB0L, 0x0268EF78L, 0x9CCB850AL, 0x6AAABED7L,
		0xC2D7F5F3L, 0x01E4C4E8L, 0x5FDB4266L, 0xD83A3752L,
		0x9CA64941L, 0x3F2F3EFAL, 0x2077CBBFL, 0x4B046864L,
		0x33C040E9L, 0xB17A057FL, 0xC2CEBF84L, 0x92A3D3B3L,
		0x3B803FC2L, 0x2FBAACF5L, 0xCD08A0A7L, 0xA61EFAC3L,
		0x369F85AEL, 0x9614009BL, 0x1481932DL, 0x279E2645L,
		0xDD2F2F91L, 0xB5AB540DL, 0x3EDD7F22L, 0xCB52391BL,
		0x72BC36BCL, 0xABB56089L, 0x89D31DE7L, 0x1D50EB1DL,
		0x651EFE74L, 0x9A0DF7BBL, 0x1DB885D4L, 0xC09F5259L,
		0xDEDE19FDL, 0x0D025EB3L, 0x06152D5CL, 0x85385375L,
		}, {
		0xC91D3A82L, 0xC79228C4L, 0x516D9B16L, 0xEAF41822L,
		0xA82B1EE5L, 0x92BBB1BAL, 0xC97072C4L, 0x0AF2D626L,
		0xEC9CC306L, 0xEA07F8F4L, 0x773CA5D5L, 0x7986D9D4L,
		0xB5AA732DL, 0xF87C05C9L, 0x84134310L, 0x6B5A33B9L,
		0x44E87BC3L, 0xCBF5050DL, 0xEC3C68BEL, 0x9FFB0E43L,
		0xAD9B3BDDL, 0x35DED40AL, 0x2AD14001L, 0x4EF5CFD1L,
		0x7D263782L, 0x25F3A325L, 0x08B9EBECL, 0x330F6D68L,
		0xF9A5D1DBL, 0x5B3BDB94L, 0x01D20F47L, 0xA6B89829L,
		0x6D657C3CL, 0x9D32C68AL, 0x8A389DDCL, 0x0AF1A252L,
		0xB5E9CBA5L, 0x74CA996BL, 0x59E7C040L, 0xE23C06B8L,
		0x3B69ECDAL, 0x53BD1E12L, 0xCD81D8F6L, 0x71B998F3L,
		0xD6CA4414L, 0x053B7355L, 0x76EAB1B4L, 0x7DCA92A1L,
		0x8D8CB7DFL, 0x44F26572L, 0x50723790L, 0xF4810D93L,
		0x93B1EFBDL, 0xE9EA4046L, 0xE6E9A0EEL, 0x187FACAEL,
		0xEA333CA2L, 0xD5E99BD0L, 0x916B8543L, 0x20752B5AL,
		0x6554E503L, 0xAAA61EADL, 0x36EEEF1CL, 0x70121EA8L,
		0x0E6DC468L, 0xAB6799C3L, 0xA8265566L, 0xF736E100L,
		0x03E20313L, 0xD8181980L, 0xE6E24B96L, 0xB21E489AL,
		0x5B3C553CL, 0x23A49DD3L, 0xAFC418B6L, 0xA807B571L,
		0xC3BE8C15L, 0xCCDB14A4L, 0x9C77E8D3L, 0x1FCED935L,
		0x25E82D1FL, 0x7838ED17L, 0xA57BA392L, 0x28E97B23L,
		0x60941D05L, 0x663AFDD9L, 0xD913FE52L, 0x10B0E9C8L,
		0x01C090B6L, 0x921E2C4DL, 0x6BD9488CL, 0x68E1429DL,
		0x2AA87E7BL, 0xC8BA1070L, 0xD66DA3E0L, 0x0F66884FL,
		0x1648AF43L, 0xA239A8DCL, 0xE4964AD0L, 0x8068A066L,
		0x91E4408CL, 0x0321B7E0L, 0x3F33A264L, 0xB72CC578L,
		0x6C1C912EL, 0xED757723L, 0xC9FA20FCL, 0x13CC343CL,
		0xE7056942L, 0x19CE5761L, 0x35AD4DB2L, 0xBC76D4B9L,
		0x68C59615L, 0x723C3060L, 0xF57C23BCL, 0xE7D6BCADL,
		0x00F46073L, 0xB9127D8FL, 0x44CAD49AL, 0x9A5D6B11L,
		0xE394A7F5L, 0xEB3F968EL, 0xCD7520E0L, 0x1D9D8244L,
		0x555C55E9L, 0x25DA7BB1L, 0x3AFFA7F4L, 0x0575DEBFL,
		0x55C48D52L, 0x5ADC4DD8L, 0x2EB346EBL, 0x671D6AD8L,
		0x2B128FD9L, 0x9DF0D831L, 0x0B6C6C94L, 0x9166356EL,
		0xA702A705L, 0xA3DD56C0L, 0x31C990E4L, 0x07C4E326L,
		0x4F058C61L, 0xB4F45D31L, 0x1F555F53L, 0x269FB055L,
		0xB6852ACAL, 0x7879C55BL, 0xF18A8256L, 0x82E1E5A6L,
		0x16FCDBD6L, 0x3C53EE12L, 0x1DDAAE76L, 0x3B6DF49EL,
		0x5B4CAE04L, 0xB2353A19L, 0x3080F4B9L, 0xF3040CD0L,
		0xB8492621L, 0xDAC10038L, 0x5FA35637L, 0xF5D9CF83L,
		0x1077D5C6L, 0x213793E7L, 0xA5395A0AL, 0x728003E1L,
		0xD90C5F36L, 0xC945ADCEL, 0x73421F88L, 0x694C1D59L,
		0xDE84F347L, 0x4EAF0AB7L, 0x4D50A504L, 0x43DAFEC9L,
		0x821829B9L, 0x7F532504L, 0x765F31E4L, 0x21C07C08L,
		0xA3C0D55BL, 0x5E7B542AL, 0x8E5C6600L, 0xFD12640BL,
		0xB7953AD1L, 0x864A78FEL, 0xDE548E94L, 0x8792B188L,
		0x9E29E5BCL, 0xC0186398L, 0x8A39DA22L, 0x8883F7E0L,
		0x4EE058B7L, 0x412FDB69L, 0x9AE59311L, 0x2466223DL,
		0xFEE86ABDL, 0x56CE7230L, 0xCFEC05F2L, 0x47DCEE78L,
		0x837A5D28L, 0x6E9D94EEL, 0xE04A5AD2L, 0xC701696CL,
		0x8E9AD861L, 0x432B3647L, 0x251C48C7L, 0x2504D178L,
		0x69702645L, 0x986348BDL, 0xD5BFB37CL, 0x741B7248L,
		0x23EBB3AEL, 0x2D522818L, 0xAD77F3EDL, 0x68C547D0L,
		0x7CCCA781L, 0x8FA511DCL, 0x3789CBB4L, 0x98344AECL,
		0xA5E96DD4L, 0xEDE3622BL, 0x4E000F33L, 0xBE4FD4D1L,
		0x588C6F9EL, 0xBDE284B9L, 0x44643084L, 0x518DA9CBL,
		0xBA7FCF3DL, 0x1556ECB9L, 0x10864FA2L, 0x02EA6B94L,
		0xED02E932L, 0x2C507C14L, 0x329E9866L, 0x79E1C795L,
		0xF63BEB62L, 0x1DE7EB1EL, 0x45107AD3L, 0x77E2ABFBL,
		0x526A6CD2L, 0x5BA1946FL, 0x3257D238L, 0xFAB2FB30L,
		0xD1983860L, 0x9943CA36L, 0x496D6BD3L, 0xF22CF09BL,
		0xCCEC9071L, 0x579FBDD0L, 0xCB814591L, 0xE6DFFDBBL,
		0xBE16F8DFL, 0xA87C9A49L, 0xE6536354L, 0x512ADE24L,
		0xB657E640L, 0xAF938431L, 0xEDF03A94L, 0x350CF9D0L,
		}, {
		0x832696C3L, 0xC83E3F7CL, 0xF7ABFCD7L, 0xB4C19D26L,
		0x8875C200L, 0xC6BB64CAL, 0xE1637C82L, 0x67E46AAEL,
		0x2D57A570L, 0x633F6CEEL, 0xBC6F56EAL, 0xC358274DL,
		0x8C481858L, 0x2F8C3351L, 0x92B1E9D9L, 0xF860AC88L,
		0x24320781L, 0xA5DDEE92L, 0x1F5BF31CL, 0x6ED0AE60L,
		0x0B285558L, 0x06EC438CL, 0x70E85A6BL, 0xED439238L,
		0x4BFC6DE6L, 0x8FB8144BL, 0x0BF039AFL, 0xDB9ABC52L,
		0x96FF2429L, 0x392586F8L, 0x2D1115E2L, 0x8D866F1EL,
		0xCA24A8BAL, 0x51EF2664L, 0x455B4EEEL, 0x5BBE3978L,
		0xC09A03A1L, 0x65BD9F62L, 0xDDC17919L, 0x70A8FDF4L,
		0xD5C3973DL, 0x7E5BE10DL, 0xB0B8C4F8L, 0x62F9D805L,
		0xD68535CFL, 0x4B144C86L, 0x24A11180L, 0xC3A954FAL,
		0xFAC22023L, 0xCD7E8E6FL, 0xD337D770L, 0x56911E62L,
		0x8F774493L, 0x6F9DACEBL, 0x60413828L, 0xD3B99186L,
		0xBE8E60E9L, 0xC9D4324EL, 0x3E590D8FL, 0xA6701D7EL,
		0xC7266E0CL, 0x22BE9A94L, 0xEC59F354L, 0x5A5C408AL,
		0xDB19D3BAL, 0xA5977A8DL, 0xC8FFCAC5L, 0x56EE41D9L,
		0xC2F3173EL, 0x6BB40320L, 0x404653B6L, 0x224CFF01L,
		0x43934AF1L, 0x70254314L, 0x712D7040L, 0x1ED7B45EL,
		0x2F4DA29FL, 0xD0BD94A9L, 0x10729CDBL, 0xBEA38FE7L,
		0xB41EB6F6L, 0x36DC612AL, 0x5FFECAA6L, 0x0A1A4588L,
		0x34494826L, 0x9CF0B3C2L, 0xCF5540AFL, 0xAE8FDACAL,
		0x4595D88CL, 0x2A04B6C7L, 0xD3CA223CL, 0x00F098BAL,
		0x87BFF1EBL, 0x0F21728EL, 0x3A4CC2FBL, 0x7646FB6FL,
		0x9287DE8EL, 0x5A22DBBCL, 0x9CA788D0L, 0x3955C8ECL,
		0xEF65AD58L, 0xED39CC0CL, 0xA9BCA738L, 0x441DF384L,
		0x069C63B0L, 0xFC2E1295L, 0xCBBA6E89L, 0x62E0484EL,
		0xA964A170L, 0x80C8B564L, 0xF0145F20L, 0x585D6976L,
		0x8A6FECB4L, 0x2B5B9BFDL, 0xB41BD3CDL, 0x4D26C783L,
		0xF2518446L, 0xF8E2F546L, 0x28E1EC7BL, 0x5891BD6EL,
		0x6F37030FL, 0x76F3F25DL, 0x6ADA036EL, 0xED521D56L,
		0x8CEF9F66L, 0x776D4ED8L, 0x7B9075BEL, 0x1C19328CL,
		0xBC82A9D5L, 0x90A12333L, 0xA73F84AEL, 0xCE8C0EE6L,
		0x6532882AL, 0x54DE205DL, 0x8AB9342FL, 0xE9164823L,
		0xA7EF738AL, 0x2B09F3F3L, 0x25CD2BABL, 0xDC1ADA2DL,
		0xABFE0427L, 0xA996D8C4L, 0x4EA32AFDL, 0xF9559F4EL,
		0x62ECB2AEL, 0x63B27945L, 0x3DDDB6FAL, 0xD0C864BBL,
		0x2B3B0259L, 0xBC52392DL, 0x5D7D8C93L, 0xA42A7C17L,
		0x781DD59FL, 0x32281898L, 0x40304092L, 0x31CA351BL,
		0xDBDD120DL, 0xE97F8A7CL, 0x4B08951FL, 0x76158668L,
		0xD40A28E9L, 0xB3AE8EA9L, 0xE9F00EFCL, 0x08E8464DL,
		0x449FAA32L, 0xB6378741L, 0xC928F6FAL, 0xF776248CL,
		0x78C1E863L, 0xF89A3E1CL, 0xD931ACA6L, 0xC7EC5FAAL,
		0xD3F2712DL, 0x6B82E088L, 0x054D5937L, 0x1DE35A13L,
		0x8805365AL, 0x5C5F501BL, 0x4DA49154L, 0xF2C4DE1BL,
		0x3FB9A18DL, 0x7E0D9F63L, 0x852DDD24L, 0xF08B2B10L,
		0x8A3F44FDL, 0xF5A7B732L, 0x5C2EF81EL, 0x8223A0FFL,
		0x8AAD1618L, 0xC920D93FL, 0x82E09782L, 0xC640D537L,
		0xA8085A33L, 0x562CE081L, 0x1FBB19A2L, 0xAA655FE1L,
		0x1302E190L, 0x41CC80B0L, 0x2C8013C0L, 0x0CBED39FL,
		0xE9B9178AL, 0xE109E701L, 0xB77382B7L, 0x067CF3A6L,
		0xCB5A8E8DL, 0xEDEB42F8L, 0x8DE95C0FL, 0x01AE6C13L,
		0xF90E2F8DL, 0xAFFED100L, 0xB83EF6CEL, 0x2C16D9ECL,
		0x8C9C016EL, 0xCC191879L, 0xC4D838EBL, 0xA149B638L,
		0x2F5DACFBL, 0x55CF002DL, 0x89C3E05AL, 0x727573B3L,
		0x3F20E481L, 0xA3CBF5CDL, 0xBF346FAEL, 0xBEEC614BL,
		0x1E0661F3L, 0xD27BE7DAL, 0xDD416072L, 0xB14BB755L,
		0x62023B9AL, 0xDC3B40B3L, 0x20B6CDF8L, 0x272AF7A1L,
		0xBA8E98CBL, 0xD55DEB6CL, 0x92C024F5L, 0x2EB140DDL,
		0x1C2FD4DAL, 0x285F0494L, 0x34EE1057L, 0x9CC4D0FDL,
		0x8BA6A4A8L, 0x37683654L, 0x16161DE8L, 0xD59B4D73L,
		0xBA3035F4L, 0x2C290032L, 0x8F44CBA9L, 0x77CC1C17L,
		0x46AD0EB6L, 0xEB3BBFCCL, 0x5BA5713CL, 0x454AFBC3L,
		0x189F5B99L, 0x486E7084L, 0xE217D683L, 0x16164931L,
		}};

#endif /* _CRYPT_KEY_OUTPUT_H */