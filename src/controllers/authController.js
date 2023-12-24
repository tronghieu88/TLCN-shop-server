const crypto = require("crypto");
//middleware
const catchAsyncHandler = require("../middleware/async");
const ErrorResponse = require("../utils/ErrorResponse");
const sendToken = require("../utils/jwtToken");
const User = require("../models/user/User");
const Address = require("../models/user/Address");
const { renderGmailVerify } = require("../data/email");
const sendEmailGrid = require("../utils/sendEmailGrid");
const mongoose = require("mongoose");
//
const sendEmail = require("../utils/sendEmail");
class authController {
  // [POST] /login
  login = catchAsyncHandler(async (req, res, next) => {
    const { email, password } = req.body;
    // check empty
    console.log(email, password);
    if (!email || !password) {
      return next(
        // new ErrorResponse(`Nhập thiếu thông tin`, 400)
        res.status(400).json({
          success: false,
          message: `Thiếu thông tin!`,
        })
      );
    }
    const user = await User.findOne({
      email,
    }).select("+password");
    console.log(user);
    if (!user)
      return next(
        // new ErrorResponse(`Người dùng chưa đưang ký.`, 404)
        res.status(404).json({
          success: false,
          message: `Tài khoản chưa được đăng ký! \nVui lòng đăng ký tài khoản!`,
        })
      );
    // Checks if password is correct or not
    if (!user.enable) {
      console.log("first");
      return next(
        // new ErrorResponse(`Người dùng chưa xác thực, vui lòng xác thực`, 404)
        res.status(404).json({
          success: false,
          message: `Người dùng chưa xác thực, vui lòng xác thực`,
        })
      );
    }
    const isPasswordMatched = await user.comparePassword(password);
    if (!isPasswordMatched) {
      // return await next(
      //   new ErrorResponse(`Sai thông tin tài khoản hoặc mật khẩu.`, 401)
      // );
      console.log("first");

      return next(
        res.status(401).json({
          success: false,
          message: `Sai thông tin tài khoản hoặc mật khẩu.`,
        })
      );
    }

    sendToken(user, 200, res);
  });
  //[POST] /register
  register = catchAsyncHandler(async (req, res, next) => {
    const { email, password, gender, addressForm, phone, name } = req.body;
    if (!email | !password) {
      return next(
        // new ErrorResponse(`Thiếu thông tin tài khoản hoặc mật khẩu`, 400)
        res.status(400).json({
          success: false,
          message: `Tài khoản hoặc mật khẩu không đầy đủ!`,
        })
      );
    }
    const user = await User.findOne({
      email: email,
    });

    if (user && user.enable)
      return next(
        // new ErrorResponse(`Email này đã tồn tại`, 400)
        res.status(400).json({
          success: false,
          message: `Email này đã tồn tại`,
        })
      );
    if (user && !user.enable) {
      await User.findByIdAndDelete(user._id);
    }
    const newUser = new User({
      email,
      password,
      addresses: [],
      gender,
      phone,
      name,
    });
    const newAddress = await Address.create(addressForm.detailAddress);
    addressForm.detailAddress = newAddress;
    newUser.addresses.push({
      ...addressForm,
      address: `${addressForm.address}`,
      detailAddress: newAddress,
    });
    const verifyToken = newUser.verifyEmailToken();
    await newUser.save();
    // send email
    // const resetUrl = `${req.protocol}://${req.get('host')}/api/auth/verify-email/${verifyToken}`;
    const Url = `${process.env.CLIENT}/verify-email?Token=${verifyToken}`;

    const message = {
      Tittle: "Xác thực tài khoản",
      Url,
      content: `Cảm ơn bạn đa ghé thăm website của chúng tôi . Vui lòng ấn vào nút bên duới để tiến hành xác minh tài khoản.`,
      buttonContent: `Xác thực tài khoản`,
    };
    // const message = `Your verify token for active ${newUser.name} is as follow:\n\n${resetUrl}\n\nLink will be expired after 5 minutes\n\nIf you have not requested this email, then ignore it.`
    try {
      const formData = {
        user: newUser.email,
        subject: "Xác thực tài khoản.",
        mail: renderGmailVerify(message),
      };
      sendEmailGrid(formData);
      // sendEmail(formData);
      res.status(200).json({
        success: true,
        user: newUser,
        message: `Kiểm tra email để xác thực`,
      });
    } catch (e) {
      newUser.emailCodeExpires = undefined;
      newUser.emailCodeToken = undefined;
      await newUser.save({
        validateBeforeSave: false,
      });
      console.log("e");
      console.log(e);

      return next(
        // new ErrorResponse(e.message, 500)
        res.status(401).json({
          success: false,
          message: `Sai thông tin tài khoản hoặc mật khẩu.`,
        })
      );
    }
  });
  // [POST] /refreshToken
  verifyRefreshToken = catchAsyncHandler(async (req, res, next) => {
    const { refreshToken } = req.body;
    if (!refreshToken)
      return next(
        // new ErrorResponse("Missing refresh token", 404)
        res.status(404).json({
          success: false,
          message: `Đã xảy ra lỗi! Hãy đăng nhập lại!`,
        })
      );
    const hashToken = crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex");
    console.log("HASH" + hashToken);
    const user = await User.findOne({
      refreshToken: hashToken,
      refreshTokenExpires: {
        $gt: Date.now(),
      },
    });
    if (!user)
      return next(
        // new ErrorResponse(
        //   "Invalid refresh token or expired, Login again", 404

        // )
        res.status(404).json({
          success: false,
          message: `Đã xảy ra lỗi! Hãy đăng nhập lại!`,
        })
      );
    sendToken(user, 200, res);
  });
  // [POST] /verify-email/:token
  verifyEmail = catchAsyncHandler(async (req, res, next) => {
    try {
      const session = await mongoose.startSession();
      session.startTransaction();
      const { Token } = req.body;
      // Hash URL token
      const verifyToken = crypto
        .createHash("sha256")
        .update(Token)
        .digest("hex");
      const user = await User.findOne({
        emailCodeToken: verifyToken,
        emailCodeExpires: {
          $gt: Date.now(),
        },
      });

      if (!user) {
        return next(
          // new ErrorResponse(
          //   "Xác minh mã thông báo không hợp lệ, hoặc đã hết hạn",
          //   400
          // )
          res.status(400).json({
            success: false,
            message: `Mã thông báo không hợp lệ, hoặc đã hết hạn! Hãy đăng nhập lại!`,
          })
        );
      }
      user.enable = true;
      user.emailCodeExpires = undefined;
      user.emailCodeToken = undefined;
      await user.save({
        validateBeforeSave: false,
      });
      await session.commitTransaction();
      session.endSession();
      sendToken(user, 200, res);
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      return next(
        // new ErrorResponse("Có lỗi xảy ra  vui long thử lại", 500)
        res.status(500).json({
          success: false,
          message: `Đã có lỗi xảy ra! Vui lòng thử lại sau!`,
        })
      );
    }
  });
  // [POST] /logout
  logOut = catchAsyncHandler(async (req, res, next) => {
    res.cookie(`accessToken`, null, {
      expires: new Date(Date.now()),
      httpOnly: true,
    });
    res.status(200).json({
      success: true,
      message: "Logout successfully",
    });
  });
  //[POST] /password/forgot
  forgotPassword = catchAsyncHandler(async (req, res, next) => {
    try {
      const session = await mongoose.startSession();
      session.startTransaction();
      const user = await User.findOne({
        email: req.body.email,
      });
      if (!user)
        return next(
          // new ErrorResponse("Email này chưa được đăng ký. ", 404)
          res.status(404).json({
            success: false,
            message: `Tài khoản chưa được đăng ký!`,
          })
        );

      const resetPasswordToken = user.verifyEmailToken();

      await user.save();

      // Mail sending
      // Create reset password url
      const Url = `${process.env.CLIENT}/retypepass?Token=${resetPasswordToken}`;
      // const Url = `${process.env.CLIENT}/verify-email?Token=${verifyToken}`
      const message = {
        Tittle: "Quên mật khẩu.",
        Url,
        content: `Cảm ơn bạn đa ghé thăm website của chúng tôi . Vui lòng ấn vào nút bên duới để tiến hành đặt lại mật khẩu.`,
        buttonContent: `Đặt lại mật khẩu`,
      };
      const formData = {
        user: user.email,
        subject: "Quên mật khẩu.",
        mail: renderGmailVerify(message),
      };
      // await sendEmailGrid(formData)
      await sendEmail(formData);
      await session.commitTransaction();
      session.endSession();
      res.status(200).json({
        success: true,
        message: `Kiểm tra email để đặt lại mật khẩu: ${user.email}`,
      });
    } catch (e) {
      await session.abortTransaction();
      session.endSession();

      return next(
        // new ErrorResponse(e.message, 500)
        res.status(500).json({
          success: false,
          message: e.message,
        })
      );
    }
  });
  //[PUT]  /password/resetpassword/:token
  resetPassword = catchAsyncHandler(async (req, res, next) => {
    try {
      const session = await mongoose.startSession();
      session.startTransaction();
      const { token, password, confirmPassword } = req.body;
      if (password !== confirmPassword) {
        return next(
          // new ErrorResponse("Mật khẩu không khớp.", 404)
          res.status(404).json({
            success: false,
            message: `Mật khẩu đã nhập không khớp!`,
          })
        );
      }
      const verifyToken = crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");
      const user = await User.findOne({
        emailCodeToken: verifyToken,
        emailCodeExpires: {
          $gt: Date.now(),
        },
      });
      if (!user) {
        await session.abortTransaction();
        session.endSession();
        return next(
          // new ErrorResponse(
          //   "Xác minh mã thông báo không hợp lệ, hoặc đã hết hạn.",
          //   404
          // )
          res.status(404).json({
            success: false,
            message: `Mã xác minh không hợp lệ hoặc hết hạn!`,
          })
        );
      }
      user.password = password;
      await user.save({
        validateBeforeSave: false,
      });
      await session.commitTransaction();
      session.endSession();
      res.status(200).json({
        success: true,
        message: `Mật khẩu đã được đặt lại.`,
      });
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      return next(
        // new ErrorResponse(error, 500)
        res.status(500).json({
          success: false,
          message: error,
        })
      );
    }
  });
  //[PUT] /password/change
  changePassword = catchAsyncHandler(async (req, res, next) => {
    try {
      const session = await mongoose.startSession();
      session.startTransaction();
      const user = await User.findById(req.user._id).select("+password");
      if (!user)
        return next(
          // new ErrorResponse("User not found", 404)
          res.status(404).json({
            success: false,
            message: `Không tìm thấy người dùng!`,
          })
        );
      const { oldPassword, newPassword, confirmNewPassword } = req.body;
      if (!newPassword || !newPassword || !oldPassword)
        return next(
          // new ErrorResponse("Không được bỏ trống,", 400)
          res.status(400).json({
            success: false,
            message: `Không được bỏ trống!`,
          })
        );
      const checkPassword = await user.comparePassword(oldPassword);
      if (!checkPassword)
        return next(
          // new ErrorResponse("Mật khẩu cũ không đúng.", 400)
          res.status(400).json({
            success: false,
            message: `Sai mật khẩu!`,
          })
        );
      if (newPassword !== confirmNewPassword) {
        return next(
          // new ErrorResponse("Mật khẩu không khớp.", 400)
          res.status(400).json({
            success: false,
            message: `Mật khẩu đã nhập không khớp!`,
          })
        );
      }
      user.password = newPassword;
      await user.save({
        validateBeforeSave: false,
      });
      await session.commitTransaction();
      session.endSession();
      sendToken(user, 200, res);
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      return next(
        // new ErrorResponse("Đã xay ra lỗi .", 500)
        res.status(500).json({
          success: false,
          message: `Đã xảy ra lỗi! Vui lòng đăng nhập lại!`,
        })
      );
    }
  });
}

module.exports = new authController();
