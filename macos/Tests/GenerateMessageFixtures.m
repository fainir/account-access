#import <Foundation/Foundation.h>
int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 2) return 2;
        NSString *shortText = @"Example [login]: 121212";
        NSString *unicode = [[@"שלום 🧪 " stringByPaddingToLength:400 withString:@"שלום 🧪 " startingAtIndex:0] stringByAppendingString:@"fictional login: 121212"];
        NSArray *values = @[
            @[@"short", shortText, [[NSAttributedString alloc] initWithString:shortText]],
            @[@"long_utf8", unicode, [[NSMutableAttributedString alloc] initWithString:unicode]],
            @[@"formatting", shortText, [[NSAttributedString alloc] initWithString:shortText attributes:@{@"FictionalAttribute": @"Other code: 654321"}]],
            @[@"github", @"121212 is your GitHub authentication code.", [[NSAttributedString alloc] initWithString:@"121212 is your GitHub authentication code."]],
            @[@"empty", @"", [[NSAttributedString alloc] initWithString:@""]],
            @[@"wrong_root", [NSNull null], @{@"text": shortText}]
        ];
        NSMutableArray *cases = [NSMutableArray array];
        for (NSArray *row in values) {
            NSData *data = [NSArchiver archivedDataWithRootObject:row[2]];
            const unsigned char *bytes = data.bytes;
            NSMutableString *hex = [NSMutableString string];
            for (NSUInteger index = 0; index < data.length; index++) [hex appendFormat:@"%02x", bytes[index]];
            [cases addObject:@{@"name": row[0], @"text": row[1], @"hex": hex}];
        }
        NSURL *target = [NSURL fileURLWithPath:[NSString stringWithUTF8String:argv[1]]];
        [[NSFileManager defaultManager] createDirectoryAtURL:[target URLByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
        NSDictionary *output = @{@"provenance": @"Fictional data serialized locally with Apple Foundation NSArchiver; no private Messages data", @"cases": cases};
        NSData *json = [NSJSONSerialization dataWithJSONObject:output options:NSJSONWritingPrettyPrinted error:nil];
        if (![json writeToURL:target atomically:YES]) return 1;
        printf("Generated %lu fictional Foundation archive fixtures\n", (unsigned long)cases.count);
    }
    return 0;
}
