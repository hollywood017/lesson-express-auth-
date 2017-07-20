const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const myCamelSchema = new Schema(
  {
    name:{
      type: String,
      required: true
    },
    color:{
      type: String,
      required: true
    },
    humps:{
      type: Number,
      required :true,
      default: 2,
      min: 1,
      max: 2
    },
      user:{
        type: Schema.Types.ObjectId,
        required: true,
        ref: 'User'  //"ref" is the string name of a model that the ID refers to
                    // you NEED "ref" to use "populate()"
      }
  },
  {
    timestamps: true
  }
);

const CamelModel = mongoose.model('Camel', myCamelSchema);

module.exports = CamelModel;
