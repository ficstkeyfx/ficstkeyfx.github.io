---
title : "Hack The Box - Tear Or Dear"
author: imdang 🤞🤞
date: 2024-11-13 11:33:00 +0800
categories: [Hackthebox, Hackthebox-Reverse, Hackthebox-Easy]
tags: [reverse, exe, dnspy]
---

<!-- ![image](https://user-images.githubusercontent.com/59029171/139866885-bc8556d4-7979-4d42-9d4e-027c0900f245.png) -->

<!-- **Node is about enumerating an Express NodeJS application to find an API endpoint that discloses the usernames and password hashes. To root the box is a simple buffer overflow and possible by three other unintended ways.** -->


# Solution

The first thing that I do is use ```file``` and ```string```.

```shell
.NETFramework,Version=v4.5
FrameworkDisplayName
.NET Framework 4.5
3System.Resources.Tools.StronglyTypedResourceBuilder
4.0.0.0
KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator
```

That shows ```exe``` file write by C# use .NET Framework, so now i use ```dnspy``` to reverse it.

## DnSpy
First, try to run ```exe``` file

![image](https://raw.githubusercontent.com/ficstkeyfx/ficstkeyfx.github.io/refs/heads/main/.github/images/20241113_reverse_tearordear_exe.png)

It check for username and password and in introduction of the challenge the flag have format HTB{username:password} so challenge is finding username and password

Run in ```dnSpy``` and see that.
The program start with 

```c#
namespace TearORDear
{
  // Token: 0x02000003 RID: 3
  internal static class Program
  {
  // Token: 0x06000014 RID: 20 RVA: 0x0000335D File Offset: 0x0000155D
    [STAThread]
    private static void Main()
    {
      Application.EnableVisualStyles();
      Application.SetCompatibleTextRenderingDefault(false);
      Application.Run(new LoginForm());
    }
  }
}
```
See in ```LoginForm``` that have button1_Click are check username and password

```c#
private void button1_Click(object sender, EventArgs e)
{
  this.label_Result.Text = "";
  this.kapa(sender, e);
  this.pep = 0;
  this.aa =
  this.Multiply(this.encrypted1(this.textBox_user.Text).Substring(0, 5), -1);
  this.aa = this.aa.Remove(this.aa.Length - 1);
  string s = this.Multiply(this.oura, -9);
  if (this.username == this.o && this.check1(s))
  {
    MessageBox.Show("Correct!");
    return;
  }
  this.label_Result.Text = "WRONG CREDENTIALS! Try Again...";
}
```

The username and password have 2 conditions including ```this.username == this.o``` and ```this.check1(s)```

Now, set debug in this line and run, see that

![image](https://raw.githubusercontent.com/ficstkeyfx/ficstkeyfx.github.io/refs/heads/main/.github/images/20241113_reverse_tearordear_username.png)

Try with username ```roiw!@#``` and set debug but the condition return false. So username is not ```roiw!@#```, why.

Now, see before the conditions, get attention to ```this.Multiply(this.encrypted1(this.textBox_user.Text).Substring(0, 5), -1);```

```c#
public string Multiply(string s, int n)
{
  char[] array = s.ToCharArray();
  Array.Reverse(array);
  this.username = this.textBox_pass.Text;
  return new string(array);
}
```

The username get from password :))) so the password is ```roiw!@#```

Now handle the second condition ```this.check1(s)```, it will return check2, check3, check4 and last return ```check```

```c#
private bool check(string[] s1, string s2)
{
  string[] array = new string[]
  {
    "q",
    "w",
    "e",
    "r",
    "t",
    "y",
    "u",
    "i",
    "o",
    "p",
    "a",
    "s",
    "d",
    "f",
    "g",
    "h",
    "j",
    "k",
    "l",
    "z",
    "x",
    "c",
    "q",
    "b",
    "n",
    "m"
  };
  array[3] + array[8] + array[7] + array[(int)Math.Sqrt(2.0)];
  return this.textBox_user.Text == this.aa && array[0] == array[22];
}
```
So set debug in this and we can see the username in ```this.aa``` is ```piph```

Flag: ```HTB{piph:roiw!@#}```

# Box Rooted 

![image](https://raw.githubusercontent.com/ficstkeyfx/ficstkeyfx.github.io/refs/heads/main/.github/images/20241113_reverse_tearordear_chlroot.png)

<!-- HTB Profile : [ficstkeyfx](https://app.hackthebox.com/profile/244565) -->

If you find my articles interesting, you can buy me a coffee 

<a href="https://www.buymeacoffee.com/0xStarlight"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me an OSCP?&emoji=&slug=0xStarlight&button_colour=b86e19&font_colour=ffffff&font_family=Poppins&outline_colour=ffffff&coffee_colour=FFDD00" /></a>
