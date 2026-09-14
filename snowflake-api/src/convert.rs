//! Snowflake's Arrow encoding to native Arrow types.
//!
//! Snowflake ships timestamps as `{epoch, fraction}` structs or scaled
//! integers, TIME as scaled integers, and `NUMBER(p, s>0)` as plain
//! integers, with the real type in the field metadata (`logicalType`,
//! `scale`, `precision`). This mirrors gosnowflake's `arrowToRecord`:
//!
//! ```text
//! FIXED  Int8..Int64, scale>0        -> Decimal128(precision, scale)
//! TIMESTAMP_NTZ  struct | Int64      -> Timestamp(unit, None)
//! TIMESTAMP_LTZ  struct | Int64      -> Timestamp(unit, "+00:00")
//! TIMESTAMP_TZ   struct              -> Timestamp(unit, "+00:00")   (offset dropped)
//! TIME   Int32 | Int64, scaled       -> Time32 / Time64
//! ```
//!
//! `unit` follows the column scale: 0 -> seconds, 1..3 -> milliseconds,
//! 4..6 -> microseconds, 7..9 -> nanoseconds, so values never lose
//! precision and nanosecond overflow only matters for columns declared
//! with nanosecond scale.

use std::sync::Arc;

use arrow_array::cast::AsArray;
use arrow_array::types::{
    ArrowTimestampType, Decimal128Type, Int32Type, Int64Type, Time32MillisecondType,
    Time32SecondType, Time64MicrosecondType, Time64NanosecondType, TimestampMicrosecondType,
    TimestampMillisecondType, TimestampNanosecondType, TimestampSecondType,
};
use arrow_array::{Array, ArrayRef, PrimitiveArray, RecordBatch, StructArray};
use arrow_cast::cast;
use arrow_schema::{ArrowError, DataType, Field, FieldRef, Schema, TimeUnit};

const LOGICAL_TYPE: &str = "logicalType";
const SCALE: &str = "scale";
const PRECISION: &str = "precision";
const NANOS_PER_SECOND_DIGITS: u32 = 9;

/// Rewrite every column whose metadata says it is a scaled number, a
/// timestamp, or a time into the matching native Arrow type. Columns that
/// need no change are shared, not copied.
pub fn convert_batch(batch: &RecordBatch) -> Result<RecordBatch, ArrowError> {
    let schema = batch.schema();
    let mut fields: Vec<FieldRef> = Vec::with_capacity(schema.fields().len());
    let mut columns: Vec<ArrayRef> = Vec::with_capacity(schema.fields().len());
    let mut changed = false;

    for (field, column) in schema.fields().iter().zip(batch.columns()) {
        if let Some(converted) = convert_column(field, column)? {
            changed = true;
            fields.push(Arc::new(
                Field::new(
                    field.name(),
                    converted.data_type().clone(),
                    field.is_nullable(),
                )
                .with_metadata(field.metadata().clone()),
            ));
            columns.push(converted);
        } else {
            fields.push(Arc::clone(field));
            columns.push(Arc::clone(column));
        }
    }

    if !changed {
        return Ok(batch.clone());
    }
    let schema = Arc::new(Schema::new_with_metadata(fields, schema.metadata().clone()));
    RecordBatch::try_new(schema, columns)
}

fn meta_i64(field: &Field, key: &str) -> Option<i64> {
    field.metadata().get(key)?.trim().parse().ok()
}

fn convert_column(field: &Field, column: &ArrayRef) -> Result<Option<ArrayRef>, ArrowError> {
    let Some(logical) = field.metadata().get(LOGICAL_TYPE) else {
        return Ok(None);
    };
    let scale = meta_i64(field, SCALE).unwrap_or(0);
    let is_int = |dt: &DataType| {
        matches!(
            dt,
            DataType::Int8 | DataType::Int16 | DataType::Int32 | DataType::Int64
        )
    };

    match (logical.as_str(), column.data_type()) {
        ("FIXED", dt) if scale > 0 && is_int(dt) => {
            let precision = meta_i64(field, PRECISION).unwrap_or(38).clamp(1, 38);
            let ints = cast(column, &DataType::Int64)?;
            let decimals: PrimitiveArray<Decimal128Type> = ints
                .as_primitive::<Int64Type>()
                .unary(i128::from)
                .with_precision_and_scale(
                    u8::try_from(precision).unwrap_or(38),
                    i8::try_from(scale).map_err(|_| bad_scale(field, scale))?,
                )?;
            Ok(Some(Arc::new(decimals)))
        }
        (lt @ ("TIMESTAMP_NTZ" | "TIMESTAMP_LTZ" | "TIMESTAMP_TZ"), dt) => {
            let unit = unit_for_scale(scale);
            let ticks = match dt {
                DataType::Struct(_) => struct_ticks(field, column.as_struct(), unit)?,
                dt if is_int(dt) => scaled_ticks(field, column, scale, unit)?,
                _ => return Ok(None),
            };
            let tz: Option<Arc<str>> = if lt == "TIMESTAMP_NTZ" {
                None
            } else {
                Some(Arc::from("+00:00"))
            };
            Ok(Some(timestamp_array(&ticks, unit, tz)))
        }
        ("TIME", dt) if is_int(dt) => {
            let unit = unit_for_scale(scale);
            let ticks = scaled_ticks(field, column, scale, unit)?;
            Ok(Some(time_array(&ticks, unit)?))
        }
        _ => Ok(None),
    }
}

fn bad_scale(field: &Field, scale: i64) -> ArrowError {
    ArrowError::ComputeError(format!(
        "column {} has an unsupported scale {scale}",
        field.name()
    ))
}

fn unit_for_scale(scale: i64) -> TimeUnit {
    match scale {
        i64::MIN..=0 => TimeUnit::Second,
        1..=3 => TimeUnit::Millisecond,
        4..=6 => TimeUnit::Microsecond,
        _ => TimeUnit::Nanosecond,
    }
}

fn unit_digits(unit: TimeUnit) -> u32 {
    match unit {
        TimeUnit::Second => 0,
        TimeUnit::Millisecond => 3,
        TimeUnit::Microsecond => 6,
        TimeUnit::Nanosecond => 9,
    }
}

/// `{epoch: Int64 seconds, fraction: Int32 nanoseconds[, timezone: Int32]}`
/// to ticks in `unit`. The struct's own validity and the epoch's validity
/// both count as null.
fn struct_ticks(
    field: &Field,
    array: &StructArray,
    unit: TimeUnit,
) -> Result<PrimitiveArray<Int64Type>, ArrowError> {
    let missing = |name: &str| {
        ArrowError::SchemaError(format!(
            "timestamp column {} lacks a `{name}` child",
            field.name()
        ))
    };
    let epoch = cast(
        array
            .column_by_name("epoch")
            .ok_or_else(|| missing("epoch"))?,
        &DataType::Int64,
    )?;
    let epoch = epoch.as_primitive::<Int64Type>();
    let fraction = match array.column_by_name("fraction") {
        Some(f) => Some(cast(f, &DataType::Int64)?),
        None => None,
    };
    let fraction = fraction
        .as_ref()
        .map(arrow_array::cast::AsArray::as_primitive::<Int64Type>);

    let digits = unit_digits(unit);
    let per_second = 10_i64.pow(digits);
    let fraction_divisor = 10_i64.pow(NANOS_PER_SECOND_DIGITS - digits);

    let mut out = Vec::with_capacity(array.len());
    for i in 0..array.len() {
        if array.is_null(i) || epoch.is_null(i) {
            out.push(None);
            continue;
        }
        let secs = epoch.value(i);
        let nanos = fraction.map_or(0, |f| if f.is_null(i) { 0 } else { f.value(i) });
        let ticks = secs
            .checked_mul(per_second)
            .and_then(|t| t.checked_add(nanos / fraction_divisor))
            .ok_or_else(|| {
                ArrowError::ComputeError(format!(
                    "timestamp in column {} overflows {unit:?} ticks",
                    field.name()
                ))
            })?;
        out.push(Some(ticks));
    }
    Ok(PrimitiveArray::<Int64Type>::from(out))
}

/// Integer values in units of `10^-scale` seconds to ticks in `unit`. The
/// unit is chosen so `unit_digits >= scale`; this is an exact multiply.
fn scaled_ticks(
    field: &Field,
    column: &ArrayRef,
    scale: i64,
    unit: TimeUnit,
) -> Result<PrimitiveArray<Int64Type>, ArrowError> {
    let ints = cast(column, &DataType::Int64)?;
    let ints = ints.as_primitive::<Int64Type>();
    let shift =
        unit_digits(unit) - u32::try_from(scale.max(0)).map_err(|_| bad_scale(field, scale))?;
    let factor = 10_i64.pow(shift);
    ints.try_unary(|v| {
        v.checked_mul(factor).ok_or_else(|| {
            ArrowError::ComputeError(format!(
                "value in column {} overflows {unit:?} ticks",
                field.name()
            ))
        })
    })
}

fn timestamp_array(
    ticks: &PrimitiveArray<Int64Type>,
    unit: TimeUnit,
    tz: Option<Arc<str>>,
) -> ArrayRef {
    fn build<T: ArrowTimestampType>(
        ticks: &PrimitiveArray<Int64Type>,
        tz: Option<Arc<str>>,
    ) -> ArrayRef {
        Arc::new(ticks.reinterpret_cast::<T>().with_timezone_opt(tz))
    }
    match unit {
        TimeUnit::Second => build::<TimestampSecondType>(ticks, tz),
        TimeUnit::Millisecond => build::<TimestampMillisecondType>(ticks, tz),
        TimeUnit::Microsecond => build::<TimestampMicrosecondType>(ticks, tz),
        TimeUnit::Nanosecond => build::<TimestampNanosecondType>(ticks, tz),
    }
}

fn time_array(ticks: &PrimitiveArray<Int64Type>, unit: TimeUnit) -> Result<ArrayRef, ArrowError> {
    Ok(match unit {
        TimeUnit::Second | TimeUnit::Millisecond => {
            let narrow = cast(&(Arc::new(ticks.clone()) as ArrayRef), &DataType::Int32)?;
            let narrow = narrow.as_primitive::<Int32Type>();
            if unit == TimeUnit::Second {
                Arc::new(narrow.reinterpret_cast::<Time32SecondType>())
            } else {
                Arc::new(narrow.reinterpret_cast::<Time32MillisecondType>())
            }
        }
        TimeUnit::Microsecond => Arc::new(ticks.reinterpret_cast::<Time64MicrosecondType>()),
        TimeUnit::Nanosecond => Arc::new(ticks.reinterpret_cast::<Time64NanosecondType>()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::{
        Decimal128Array, Int16Array, Int32Array, Int64Array, StringArray, Time32MillisecondArray,
        Time64NanosecondArray, TimestampMillisecondArray, TimestampSecondArray,
    };
    use std::collections::HashMap;

    fn field(name: &str, dt: DataType, logical: &str, scale: i64, precision: i64) -> Field {
        let mut meta = HashMap::new();
        meta.insert(LOGICAL_TYPE.to_owned(), logical.to_owned());
        meta.insert(SCALE.to_owned(), scale.to_string());
        meta.insert(PRECISION.to_owned(), precision.to_string());
        Field::new(name, dt, true).with_metadata(meta)
    }

    fn timestamp_struct(
        logical: &str,
        scale: i64,
        rows: &[Option<(i64, i32)>],
    ) -> (Field, ArrayRef) {
        let epoch = Int64Array::from(rows.iter().map(|r| r.map(|(e, _)| e)).collect::<Vec<_>>());
        let fraction = Int32Array::from(rows.iter().map(|r| r.map(|(_, f)| f)).collect::<Vec<_>>());
        let children: Vec<(FieldRef, ArrayRef)> = vec![
            (
                Arc::new(Field::new("epoch", DataType::Int64, true)),
                Arc::new(epoch) as ArrayRef,
            ),
            (
                Arc::new(Field::new("fraction", DataType::Int32, true)),
                Arc::new(fraction) as ArrayRef,
            ),
        ];
        let array = StructArray::from(children);
        let f = field("ts", array.data_type().clone(), logical, scale, 0);
        (f, Arc::new(array))
    }

    fn batch(cols: Vec<(Field, ArrayRef)>) -> RecordBatch {
        let (fields, arrays): (Vec<Field>, Vec<ArrayRef>) = cols.into_iter().unzip();
        RecordBatch::try_new(Arc::new(Schema::new(fields)), arrays).unwrap()
    }

    #[test]
    fn scaled_fixed_becomes_decimal_with_same_digits() {
        let b = batch(vec![
            (
                field("n2", DataType::Int16, "FIXED", 2, 10),
                Arc::new(Int16Array::from(vec![Some(150), None, Some(-5)])),
            ),
            (
                field("n0", DataType::Int64, "FIXED", 0, 38),
                Arc::new(Int64Array::from(vec![Some(7), Some(8), Some(9)])),
            ),
        ]);
        let out = convert_batch(&b).unwrap();
        assert_eq!(
            out.schema().field(0).data_type(),
            &DataType::Decimal128(10, 2)
        );
        let dec = out.column(0).as_primitive::<Decimal128Type>();
        assert_eq!(dec.value_as_string(0), "1.50");
        assert!(dec.is_null(1));
        assert_eq!(dec.value_as_string(2), "-0.05");
        assert_eq!(
            out.schema().field(1).data_type(),
            &DataType::Int64,
            "scale 0 stays integer"
        );
        assert_eq!(
            out.schema()
                .field(0)
                .metadata()
                .get("logicalType")
                .map(String::as_str),
            Some("FIXED"),
            "metadata is kept"
        );
    }

    #[test]
    fn existing_decimal128_is_left_alone() {
        let dec = Decimal128Array::from(vec![Some(12345)])
            .with_precision_and_scale(38, 0)
            .unwrap();
        let b = batch(vec![(
            field("big", dec.data_type().clone(), "FIXED", 0, 38),
            Arc::new(dec),
        )]);
        let out = convert_batch(&b).unwrap();
        assert_eq!(
            out.schema().field(0).data_type(),
            &DataType::Decimal128(38, 0)
        );
    }

    #[test]
    fn struct_timestamps_by_logical_type_and_scale() {
        let rows = [
            Some((1_789_350_452, 750_000_000)),
            None,
            Some((-1, 500_000_000)),
        ];
        let (ntz, ntz_arr) = timestamp_struct("TIMESTAMP_NTZ", 9, &rows);
        let (ltz, ltz_arr) = timestamp_struct("TIMESTAMP_LTZ", 9, &rows);
        let (tz, tz_arr) = timestamp_struct("TIMESTAMP_TZ", 3, &rows);
        let b = batch(vec![
            (ntz, ntz_arr),
            (
                Field::new("ltz", ltz.data_type().clone(), true)
                    .with_metadata(ltz.metadata().clone()),
                ltz_arr,
            ),
            (
                Field::new("tz", tz.data_type().clone(), true).with_metadata(tz.metadata().clone()),
                tz_arr,
            ),
        ]);
        let out = convert_batch(&b).unwrap();

        assert_eq!(
            out.schema().field(0).data_type(),
            &DataType::Timestamp(TimeUnit::Nanosecond, None)
        );
        let ntz = out.column(0).as_primitive::<TimestampNanosecondType>();
        assert_eq!(ntz.value(0), 1_789_350_452_750_000_000);
        assert!(ntz.is_null(1));
        assert_eq!(ntz.value(2), -500_000_000);

        assert_eq!(
            out.schema().field(1).data_type(),
            &DataType::Timestamp(TimeUnit::Nanosecond, Some("+00:00".into()))
        );
        assert_eq!(
            out.schema().field(2).data_type(),
            &DataType::Timestamp(TimeUnit::Millisecond, Some("+00:00".into()))
        );
        let tz = out.column(2).as_primitive::<TimestampMillisecondType>();
        assert_eq!(tz.value(0), 1_789_350_452_750);
        assert_eq!(tz.value(2), -500);
    }

    #[test]
    fn scaled_int_timestamps_and_times() {
        let b = batch(vec![
            (
                field("ntz0", DataType::Int64, "TIMESTAMP_NTZ", 0, 0),
                Arc::new(Int64Array::from(vec![Some(1_700_000_000), None])),
            ),
            (
                field("ltz3", DataType::Int64, "TIMESTAMP_LTZ", 3, 0),
                Arc::new(Int64Array::from(vec![Some(1_700_000_000_123), None])),
            ),
            (
                field("ntz2", DataType::Int64, "TIMESTAMP_NTZ", 2, 0),
                Arc::new(Int64Array::from(vec![Some(170_000_000_012), None])),
            ),
            (
                field("t9", DataType::Int64, "TIME", 9, 0),
                Arc::new(Int64Array::from(vec![Some(3_600_000_000_001), None])),
            ),
            (
                field("t3", DataType::Int32, "TIME", 3, 0),
                Arc::new(Int32Array::from(vec![Some(3_600_001), None])),
            ),
            (
                field("t1", DataType::Int32, "TIME", 1, 0),
                Arc::new(Int32Array::from(vec![Some(36_001), None])),
            ),
        ]);
        let out = convert_batch(&b).unwrap();
        let s = out.schema();
        assert_eq!(
            s.field(0).data_type(),
            &DataType::Timestamp(TimeUnit::Second, None)
        );
        assert_eq!(
            out.column(0).as_primitive::<TimestampSecondType>().value(0),
            1_700_000_000
        );
        assert_eq!(
            s.field(1).data_type(),
            &DataType::Timestamp(TimeUnit::Millisecond, Some("+00:00".into()))
        );
        assert_eq!(
            out.column(1)
                .as_primitive::<TimestampMillisecondType>()
                .value(0),
            1_700_000_000_123
        );
        assert_eq!(
            s.field(2).data_type(),
            &DataType::Timestamp(TimeUnit::Millisecond, None)
        );
        assert_eq!(
            out.column(2)
                .as_primitive::<TimestampMillisecondType>()
                .value(0),
            1_700_000_000_120,
            "scale 2 is widened to milliseconds exactly"
        );
        assert_eq!(
            s.field(3).data_type(),
            &DataType::Time64(TimeUnit::Nanosecond)
        );
        assert_eq!(
            out.column(3)
                .as_primitive::<Time64NanosecondType>()
                .value(0),
            3_600_000_000_001
        );
        assert_eq!(
            s.field(4).data_type(),
            &DataType::Time32(TimeUnit::Millisecond)
        );
        assert_eq!(
            out.column(4)
                .as_primitive::<Time32MillisecondType>()
                .value(0),
            3_600_001
        );
        assert_eq!(
            s.field(5).data_type(),
            &DataType::Time32(TimeUnit::Millisecond)
        );
        assert_eq!(
            out.column(5)
                .as_primitive::<Time32MillisecondType>()
                .value(0),
            3_600_100
        );
        for i in 0..6 {
            assert!(out.column(i).is_null(1));
        }
        let _ = (
            TimestampSecondArray::from(vec![0]),
            TimestampMillisecondArray::from(vec![0]),
        );
        let _ = (
            Time32MillisecondArray::from(vec![0]),
            Time64NanosecondArray::from(vec![0]),
        );
    }

    #[test]
    fn columns_without_metadata_or_of_other_types_are_shared() {
        let text: ArrayRef = Arc::new(StringArray::from(vec!["a"]));
        let b = batch(vec![
            (Field::new("plain", DataType::Utf8, true), text.clone()),
            (field("s", DataType::Utf8, "TEXT", 0, 38), text.clone()),
        ]);
        let out = convert_batch(&b).unwrap();
        assert!(Arc::ptr_eq(out.column(0), b.column(0)));
        assert!(Arc::ptr_eq(out.column(1), b.column(1)));
        assert_eq!(out.schema(), b.schema());
    }

    #[test]
    fn overflow_is_an_error_not_garbage() {
        let (f, a) = timestamp_struct("TIMESTAMP_NTZ", 9, &[Some((i64::MAX / 2, 0))]);
        let b = batch(vec![(f, a)]);
        assert!(matches!(
            convert_batch(&b),
            Err(ArrowError::ComputeError(_))
        ));
    }
}
