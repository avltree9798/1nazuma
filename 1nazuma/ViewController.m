//
//  ViewController.m
//  1nazuma
//
//  Created by Anthony Viriya on R 1/12/01.
//  Copyright © Reiwa 1 Jake James. All rights reserved.
//

#import "ViewController.h"
#import "exploit.h"
//#import "jelbrekLib/jelbrekLib.h"
#import "1nazuma_engine.h"
@interface ViewController ()

@property (weak, nonatomic) IBOutlet UITextView *log;
@property (weak, nonatomic) IBOutlet UIButton *jelbrekButton;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}

-(void) LOGText:(NSString*) text{
    NSString* currentText = [[self log] text];
    NSString* newString = [[NSString alloc] initWithFormat:@"%@\n%@",currentText, text];
    [[self log] setText:newString];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)jelbreking:(id)sender {
    [self LOGText:@"Initializing Jailbreak"];
    mach_port_t tfp0 = get_tfp0();
    if(tfp0){
         dispatch_async(dispatch_get_main_queue(), ^(void){
            [self LOGText:[[NSString alloc] initWithFormat:@"tfp0 achieved at 0x%x", tfp0]];
             [self LOGText:[[NSString alloc] initWithFormat:@"executing /bin/cat /etc/master.passwd"]];
             if(start_inazuma_engine(tfp0)==0){
                 exec("/bin/cat", 1, "/etc/master.passwd");
             }
        });
    }else{
         dispatch_async(dispatch_get_main_queue(), ^(void){
            [self LOGText:[[NSString alloc] initWithFormat:@"Failed, please re-try"]];
        });
    }
}

@end
