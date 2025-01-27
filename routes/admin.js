/** @format */

const path = require('path');
const { body } = require('express-validator');
const express = require('express');

const adminController = require('../controllers/admin');

const router = express.Router();
const isAuth = require('../middleware/is-auth');
// /admin/add-product => GET
router.get('/add-product', isAuth, adminController.getAddProduct);

// /admin/products => GET
router.get('/products', isAuth, adminController.getProducts);

// /admin/add-product => POST
router.post(
  '/add-product',
  [
    body('title')
      .isString()
      .isLength({ min: 3 })
      .trim()
      .withMessage('Title must be at least 3 characters'),
    body('price').isFloat().withMessage('Price must be a number'),
    body('description')
      .isLength({ min: 5, max: 400 })
      .withMessage('Description must be between 5 and 400 characters'),
  ],
  isAuth,
  adminController.postAddProduct
);

router.get('/edit-product/:productId', isAuth, adminController.getEditProduct);

router.post(
  '/edit-product',
  [
    body('title')
      .isString()
      .isLength({ min: 3 })
      .trim()
      .withMessage('Title must be at least 3 characters'),
    body('price').isFloat().withMessage('Price must be a number'),
    body('description')
      .isLength({ min: 5, max: 400 })
      .trim()
      .withMessage('Description must be between 5 to 400 characters'),
  ],
  isAuth,
  adminController.postEditProduct
);

router.delete('/product/:productId', isAuth, adminController.deleteProduct);

module.exports = router;
